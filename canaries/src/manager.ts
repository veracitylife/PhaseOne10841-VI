/**
 * Canary management — list, rotate marker values safely, track last trigger.
 * Markers remain harmless fakes. Ed25519 signatures for integrity (Wave B #7).
 * DEFENSIVE ONLY.
 */
import { randomBytes } from 'node:crypto';
import { CANARY_MARKERS, type CanaryMatch, matchCanaries } from './detector.js';
import {
  ensureCanaryKeys,
  signCanaryPayload,
  verifyCanaryOrWarn,
  type CanarySignatureBundle,
} from '../../shared/src/canary-sign.js';

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
  signature?: string | null;
  signature_prev?: string | null;
  public_key_id?: string | null;
  signature_bundle?: CanarySignatureBundle | null;
}

/** Runtime overlay so rotations apply without rewriting fixture files by default. */
const runtimeMarkers = new Map<string, CanaryMatch>();
const lastTriggers = new Map<
  string,
  { at: string; session_id?: string; agent_id?: string }
>();
const rotatedAt = new Map<string, string>();
const signatures = new Map<string, { current: string; prev?: string | null; keyId: string }>();

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

function signRecord(
  m: CanaryMatch,
  rotated_at?: string | null,
  prevSig?: string | null
): CanarySignatureBundle {
  const keys = ensureCanaryKeys();
  return signCanaryPayload(
    {
      canary_id: m.canaryId,
      name: m.name,
      marker: m.marker,
      rotated_at: rotated_at ?? null,
      previous_signature: prevSig ?? null,
    },
    keys
  );
}

export function listCanariesDetailed(): CanaryRecord[] {
  seedRuntime();
  const out: CanaryRecord[] = [];
  for (const [key, m] of runtimeMarkers) {
    const trig = lastTriggers.get(m.canaryId) ?? lastTriggers.get(key);
    const sig = signatures.get(key);
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
      signature: sig?.current ?? null,
      signature_prev: sig?.prev ?? null,
      public_key_id: sig?.keyId ?? null,
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
 * Rotate a canary marker to a new random harmless value and re-sign.
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
    const prevSig = signatures.get(key)?.current ?? null;
    const newMarker = `PHASEONE_CANARY_ROTATED_${m.name.replace(/[^a-zA-Z0-9]/g, '_').slice(0, 24)}_${suffix}`;
    const updated: CanaryMatch = { ...m, marker: newMarker };
    runtimeMarkers.set(key, updated);
    const ts = new Date().toISOString();
    rotatedAt.set(key, ts);
    const bundle = signRecord(updated, ts, prevSig);
    signatures.set(key, {
      current: bundle.signature,
      prev: prevSig,
      keyId: bundle.key_id,
    });
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
      signature: bundle.signature,
      signature_prev: prevSig,
      public_key_id: bundle.key_id,
      signature_bundle: bundle,
    };
  }
  return { ok: true, record: last, previous_preview: previousPreview };
}

/** Sign all active canaries (e.g. after onboard). */
export function signAllCanaries(): { signed: number; key_id: string } {
  seedRuntime();
  const keys = ensureCanaryKeys();
  let signed = 0;
  for (const [key, m] of runtimeMarkers) {
    const prev = signatures.get(key)?.current ?? null;
    const bundle = signCanaryPayload(
      {
        canary_id: m.canaryId,
        name: m.name,
        marker: m.marker,
        rotated_at: rotatedAt.get(key) ?? null,
        previous_signature: prev,
      },
      keys
    );
    signatures.set(key, { current: bundle.signature, prev, keyId: bundle.key_id });
    signed++;
  }
  return { signed, key_id: keys.keyId };
}

export function verifyAllCanaries(): Array<{
  canary_id: string;
  name: string;
  valid: boolean | null;
  warning?: string;
}> {
  seedRuntime();
  const keys = ensureCanaryKeys();
  const out: Array<{ canary_id: string; name: string; valid: boolean | null; warning?: string }> =
    [];
  for (const [key, m] of runtimeMarkers) {
    const sig = signatures.get(key);
    const result = verifyCanaryOrWarn(
      {
        canary_id: m.canaryId,
        name: m.name,
        marker: m.marker,
        rotated_at: rotatedAt.get(key) ?? null,
        previous_signature: sig?.prev ?? null,
      },
      sig?.current,
      keys.publicKeyPem
    );
    out.push({
      canary_id: m.canaryId,
      name: m.name,
      valid: result.valid,
      warning: result.warning,
    });
  }
  return out;
}

export function getCanarySignatureMeta(canaryId: string): {
  canary_signature?: string;
  canary_signature_prev?: string;
  canary_key_id?: string;
} {
  seedRuntime();
  for (const [key, m] of runtimeMarkers) {
    if (m.canaryId !== canaryId) continue;
    const sig = signatures.get(key);
    if (!sig) return {};
    return {
      canary_signature: sig.current,
      canary_signature_prev: sig.prev ?? undefined,
      canary_key_id: sig.keyId,
    };
  }
  return {};
}

export function __testResetCanaryManager(): void {
  runtimeMarkers.clear();
  lastTriggers.clear();
  rotatedAt.clear();
  signatures.clear();
}
