/**
 * Canary management — list, rotate marker values safely, track last trigger.
 * Markers remain harmless fakes. DEFENSIVE ONLY.
 */
import { randomBytes } from 'node:crypto';
import { CANARY_MARKERS, type CanaryMatch, matchCanaries } from './detector.js';

export interface CanaryRecord {
  canary_id: string;
  name: string;
  marker: string;
  marker_preview: string;
  file_hint?: string;
  rotated_at?: string | null;
  last_trigger_at?: string | null;
  last_trigger_session?: string | null;
  last_trigger_agent?: string | null;
}

/** Runtime overlay so rotations apply without rewriting fixture files by default. */
const runtimeMarkers = new Map<string, CanaryMatch>();
const lastTriggers = new Map<
  string,
  { at: string; session_id?: string; agent_id?: string }
>();
const rotatedAt = new Map<string, string>();

function seedRuntime(): void {
  if (runtimeMarkers.size) return;
  for (const m of CANARY_MARKERS) {
    const key = `${m.canaryId}::${m.name}`;
    runtimeMarkers.set(key, { ...m });
  }
}

function preview(marker: string): string {
  if (marker.length <= 16) return marker.slice(0, 4) + '…';
  return marker.slice(0, 12) + '…';
}

export function listCanariesDetailed(): CanaryRecord[] {
  seedRuntime();
  const out: CanaryRecord[] = [];
  for (const [key, m] of runtimeMarkers) {
    const trig = lastTriggers.get(m.canaryId) ?? lastTriggers.get(key);
    out.push({
      canary_id: m.canaryId,
      name: m.name,
      marker: m.marker,
      marker_preview: preview(m.marker),
      file_hint: m.name,
      rotated_at: rotatedAt.get(key) ?? null,
      last_trigger_at: trig?.at ?? null,
      last_trigger_session: trig?.session_id ?? null,
      last_trigger_agent: trig?.agent_id ?? null,
    });
  }
  return out;
}

/** Active markers for detection (includes rotated values). */
export function getActiveMarkers(): CanaryMatch[] {
  seedRuntime();
  return [...runtimeMarkers.values()];
}

export function matchCanariesRuntime(text: string): CanaryMatch[] {
  seedRuntime();
  if (!text || typeof text !== 'string') return [];
  const hits: CanaryMatch[] = [];
  const seen = new Set<string>();
  for (const c of getActiveMarkers()) {
    if (text.includes(c.marker) && !seen.has(c.canaryId + c.marker)) {
      seen.add(c.canaryId + c.marker);
      hits.push(c);
    }
  }
  // Also match shipped defaults (in case runtime was rotated away but old value still appears)
  for (const c of matchCanaries(text)) {
    if (!seen.has(c.canaryId + c.marker)) {
      seen.add(c.canaryId + c.marker);
      hits.push(c);
    }
  }
  return hits;
}

export function noteCanaryTrigger(
  canaryId: string,
  opts?: { session_id?: string; agent_id?: string; name?: string }
): void {
  const at = new Date().toISOString();
  lastTriggers.set(canaryId, {
    at,
    session_id: opts?.session_id,
    agent_id: opts?.agent_id,
  });
  if (opts?.name) {
    lastTriggers.set(`${canaryId}::${opts.name}`, {
      at,
      session_id: opts?.session_id,
      agent_id: opts?.agent_id,
    });
  }
}

/**
 * Rotate a canary marker to a new random harmless value.
 * Does not invent real credentials — prefix keeps it clearly a PhaseOne canary.
 */
export function rotateCanary(
  canaryId: string,
  name?: string
): { ok: boolean; record?: CanaryRecord; error?: string; previous_preview?: string } {
  seedRuntime();
  const entries = [...runtimeMarkers.entries()].filter(
    ([, m]) => m.canaryId === canaryId && (!name || m.name === name)
  );
  if (!entries.length) return { ok: false, error: 'canary not found' };

  const suffix = randomBytes(8).toString('hex');
  let last: CanaryRecord | undefined;
  let previousPreview: string | undefined;

  for (const [key, m] of entries) {
    previousPreview = preview(m.marker);
    const newMarker = `PHASEONE_CANARY_ROTATED_${m.name.replace(/[^a-zA-Z0-9]/g, '_').slice(0, 24)}_${suffix}`;
    const updated: CanaryMatch = { ...m, marker: newMarker };
    runtimeMarkers.set(key, updated);
    const ts = new Date().toISOString();
    rotatedAt.set(key, ts);
    last = {
      canary_id: updated.canaryId,
      name: updated.name,
      marker: updated.marker,
      marker_preview: preview(updated.marker),
      file_hint: updated.name,
      rotated_at: ts,
      last_trigger_at: lastTriggers.get(updated.canaryId)?.at ?? null,
      last_trigger_session: lastTriggers.get(updated.canaryId)?.session_id ?? null,
      last_trigger_agent: lastTriggers.get(updated.canaryId)?.agent_id ?? null,
    };
  }
  return { ok: true, record: last, previous_preview: previousPreview };
}

export function __testResetCanaryManager(): void {
  runtimeMarkers.clear();
  lastTriggers.clear();
  rotatedAt.clear();
}
