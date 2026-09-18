/**
 * Ed25519 signed canary packages — integrity checks + SIEM provenance.
 * DEFENSIVE ONLY. Private key never logged or returned via API.
 */

import {
  generateKeyPairSync,
  sign,
  verify,
  createPrivateKey,
  createPublicKey,
  type KeyObject,
} from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

export interface CanarySigningKeys {
  publicKeyPem: string;
  privateKeyPem: string;
  keyId: string;
}

export interface SignedCanaryPayload {
  canary_id: string;
  name: string;
  marker: string;
  rotated_at?: string | null;
  previous_signature?: string | null;
}

export interface CanarySignatureBundle {
  algorithm: 'ed25519';
  key_id: string;
  signature: string;
  signed_at: string;
  previous_signature?: string | null;
  payload_hash_note: 'ed25519-over-canonical-json';
}

function defaultKeyDir(): string {
  return resolve(
    process.env.PHASEONE_CANARY_KEY_DIR ?? join(process.cwd(), 'canaries', '.keys')
  );
}

function canonicalJson(payload: SignedCanaryPayload): string {
  return JSON.stringify({
    canary_id: payload.canary_id,
    marker: payload.marker,
    name: payload.name,
    previous_signature: payload.previous_signature ?? null,
    rotated_at: payload.rotated_at ?? null,
  });
}

export function generateCanaryKeyPair(): CanarySigningKeys {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const keyId = `canary-ed25519-${Date.now().toString(36)}`;
  return { publicKeyPem, privateKeyPem, keyId };
}

export function ensureCanaryKeys(keyDir = defaultKeyDir()): CanarySigningKeys {
  const privPath = join(keyDir, 'canary-ed25519.pem');
  const pubPath = join(keyDir, 'canary-ed25519.pub.pem');
  const idPath = join(keyDir, 'canary-ed25519.keyid');

  if (existsSync(privPath) && existsSync(pubPath)) {
    const privateKeyPem = readFileSync(privPath, 'utf8');
    const publicKeyPem = readFileSync(pubPath, 'utf8');
    const keyId = existsSync(idPath)
      ? readFileSync(idPath, 'utf8').trim()
      : `canary-ed25519-existing`;
    return { publicKeyPem, privateKeyPem, keyId };
  }

  mkdirSync(keyDir, { recursive: true });
  const keys = generateCanaryKeyPair();
  writeFileSync(privPath, keys.privateKeyPem, { mode: 0o600 });
  writeFileSync(pubPath, keys.publicKeyPem, { mode: 0o644 });
  writeFileSync(idPath, keys.keyId + '\n', { mode: 0o644 });
  try {
    chmodSync(privPath, 0o600);
  } catch {
    /* ignore on platforms without chmod */
  }
  return keys;
}

function loadPrivateKey(pem: string): KeyObject {
  return createPrivateKey(pem);
}

function loadPublicKey(pem: string): KeyObject {
  return createPublicKey(pem);
}

export function signCanaryPayload(
  payload: SignedCanaryPayload,
  keys?: CanarySigningKeys
): CanarySignatureBundle {
  const k = keys ?? ensureCanaryKeys();
  const data = Buffer.from(canonicalJson(payload), 'utf8');
  const signature = sign(null, data, loadPrivateKey(k.privateKeyPem)).toString('base64');
  return {
    algorithm: 'ed25519',
    key_id: k.keyId,
    signature,
    signed_at: new Date().toISOString(),
    previous_signature: payload.previous_signature ?? null,
    payload_hash_note: 'ed25519-over-canonical-json',
  };
}

export function verifyCanarySignature(
  payload: SignedCanaryPayload,
  signatureB64: string,
  publicKeyPem: string
): { ok: boolean; error?: string } {
  try {
    const data = Buffer.from(canonicalJson(payload), 'utf8');
    const sig = Buffer.from(signatureB64, 'base64');
    const ok = verify(null, data, loadPublicKey(publicKeyPem), sig);
    return ok ? { ok: true } : { ok: false, error: 'signature mismatch' };
  } catch (err) {
    return {
      ok: false,
      error: err instanceof Error ? err.message : 'verification failed',
    };
  }
}

export function getPublicKeyInfo(keyDir = defaultKeyDir()): {
  key_id: string;
  public_key_pem: string;
  key_dir: string;
} | null {
  try {
    const keys = ensureCanaryKeys(keyDir);
    return {
      key_id: keys.keyId,
      public_key_pem: keys.publicKeyPem,
      key_dir: keyDir,
    };
  } catch {
    return null;
  }
}

/** Verify without blocking startup — warn-only helper. */
export function verifyCanaryOrWarn(
  payload: SignedCanaryPayload,
  signatureB64: string | null | undefined,
  publicKeyPem?: string
): { valid: boolean | null; warning?: string } {
  if (!signatureB64) {
    return { valid: null, warning: 'canary unsigned — signing recommended for production' };
  }
  try {
    const pub = publicKeyPem ?? ensureCanaryKeys().publicKeyPem;
    const result = verifyCanarySignature(payload, signatureB64, pub);
    if (!result.ok) {
      return { valid: false, warning: `canary signature invalid: ${result.error}` };
    }
    return { valid: true };
  } catch (err) {
    return {
      valid: null,
      warning: err instanceof Error ? err.message : 'canary verify skipped',
    };
  }
}

export function keyDirPath(): string {
  return defaultKeyDir();
}

export function ensureKeyDirParent(): string {
  const dir = defaultKeyDir();
  mkdirSync(dirname(dir), { recursive: true });
  return dir;
}
