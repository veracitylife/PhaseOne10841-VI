/**
 * PhaseOne10841 Gatekeeper Event Matcher
 * Matches incoming events against playbook conditions.
 * 
 * DEFENSIVE ONLY — no exploit tooling.
 * Veracity Integrity LLC · https://VeracityIntegrity.com
 */

import type { GatekeeperEvent, Playbook, PlaybookMatch } from './types.js';

interface EventWindow {
  events: GatekeeperEvent[];
  lastCleanup: number;
}

const eventWindows = new Map<string, EventWindow>();
const playbookCooldowns = new Map<string, number>();
const playbookExecutionCounts = new Map<string, { count: number; windowStart: number }>();

function matchArray(pattern: string | string[] | undefined, value: string | undefined): boolean {
  if (!pattern) return true;
  if (!value) return false;
  
  const patterns = Array.isArray(pattern) ? pattern : [pattern];
  return patterns.some(p => {
    if (p.includes('*')) {
      const regex = new RegExp('^' + p.replace(/\*/g, '.*') + '$');
      return regex.test(value);
    }
    return p === value;
  });
}

function matchSeverity(pattern: string | string[] | undefined, value: string | undefined): boolean {
  if (!pattern) return true;
  if (!value) return false;
  
  const severityOrder = ['info', 'low', 'medium', 'high', 'critical'];
  const patterns = Array.isArray(pattern) ? pattern : [pattern];
  
  for (const p of patterns) {
    if (p.startsWith('>=')) {
      const threshold = p.slice(2);
      const thresholdIdx = severityOrder.indexOf(threshold);
      const valueIdx = severityOrder.indexOf(value);
      if (thresholdIdx !== -1 && valueIdx !== -1 && valueIdx >= thresholdIdx) {
        return true;
      }
    } else if (p === value) {
      return true;
    }
  }
  
  return false;
}

function matchSingleEvent(match: PlaybookMatch, event: GatekeeperEvent): boolean {
  if (!matchArray(match.rule_id, event.rule_id)) return false;
  if (!matchArray(match.event_type, event.event_type)) return false;
  if (!matchSeverity(match.severity, event.severity)) return false;
  if (!matchArray(match.decision, event.decision)) return false;
  if (match.agent_id && match.agent_id !== event.agent_id) return false;
  
  return true;
}

function getWindowKey(playbookId: string, match: PlaybookMatch): string {
  const parts = [playbookId];
  if (match.agent_id) parts.push(`agent:${match.agent_id}`);
  return parts.join(':');
}

function cleanupOldEvents(window: EventWindow, maxAge: number, now: number): void {
  const cutoff = now - maxAge;
  window.events = window.events.filter(e => e.timestamp >= cutoff);
  window.lastCleanup = now;
}

export function matchPlaybook(
  playbook: Playbook,
  event: GatekeeperEvent,
  now = Date.now()
): { matched: boolean; reason?: string; eventsInWindow?: number } {
  if (!playbook.enabled) {
    return { matched: false, reason: 'playbook disabled' };
  }
  
  const cooldownKey = playbook.id;
  const lastExec = playbookCooldowns.get(cooldownKey);
  if (lastExec && now - lastExec < (playbook.cooldown_ms ?? 60000)) {
    return { matched: false, reason: 'playbook in cooldown' };
  }
  
  const execData = playbookExecutionCounts.get(playbook.id);
  const windowMs = playbook.match.window_ms ?? 60000;
  if (execData) {
    if (now - execData.windowStart > windowMs) {
      playbookExecutionCounts.set(playbook.id, { count: 0, windowStart: now });
    } else if (execData.count >= (playbook.max_executions_per_window ?? 10)) {
      return { matched: false, reason: 'max executions per window reached' };
    }
  }
  
  if (!matchSingleEvent(playbook.match, event)) {
    return { matched: false, reason: 'event does not match conditions' };
  }
  
  if (playbook.match.count && playbook.match.count > 1) {
    const windowKey = getWindowKey(playbook.id, playbook.match);
    let window = eventWindows.get(windowKey);
    
    if (!window) {
      window = { events: [], lastCleanup: now };
      eventWindows.set(windowKey, window);
    }
    
    const maxAge = playbook.match.window_ms ?? 60000;
    if (now - window.lastCleanup > maxAge / 4) {
      cleanupOldEvents(window, maxAge, now);
    }
    
    window.events.push(event);
    
    const relevantEvents = window.events.filter(e => e.timestamp >= now - maxAge);
    
    if (relevantEvents.length < playbook.match.count) {
      return { 
        matched: false, 
        reason: `count threshold not met (${relevantEvents.length}/${playbook.match.count})`,
        eventsInWindow: relevantEvents.length
      };
    }
    
    return { matched: true, eventsInWindow: relevantEvents.length };
  }
  
  return { matched: true };
}

export function recordPlaybookExecution(playbookId: string, now = Date.now()): void {
  playbookCooldowns.set(playbookId, now);
  
  const execData = playbookExecutionCounts.get(playbookId);
  if (execData && now - execData.windowStart < 60000) {
    execData.count++;
  } else {
    playbookExecutionCounts.set(playbookId, { count: 1, windowStart: now });
  }
}

export function matchAllPlaybooks(
  playbooks: Playbook[],
  event: GatekeeperEvent,
  now = Date.now()
): Array<{ playbook: Playbook; eventsInWindow?: number }> {
  const matches: Array<{ playbook: Playbook; eventsInWindow?: number }> = [];
  
  for (const playbook of playbooks) {
    const result = matchPlaybook(playbook, event, now);
    if (result.matched) {
      matches.push({ playbook, eventsInWindow: result.eventsInWindow });
    }
  }
  
  return matches;
}

export function __testResetMatcher(): void {
  eventWindows.clear();
  playbookCooldowns.clear();
  playbookExecutionCounts.clear();
}
