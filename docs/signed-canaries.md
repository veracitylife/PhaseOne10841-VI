# Signed canary packages

**Phase 8 Wave B #7** · phaseone-core v0.8.0  
**Veracity Integrity LLC** · https://VeracityIntegrity.com

DEFENSIVE ONLY — Ed25519 signatures for canary integrity and SIEM provenance. Markers remain harmless fakes.

## Keys

Onboard generates keys under `canaries/.keys/` (gitignored):

- `canary-ed25519.pem` — private (mode 0600)
- `canary-ed25519.pub.pem` — public
- `canary-ed25519.keyid` — key id

Override directory with `PHASEONE_CANARY_KEY_DIR`.

## CLI

```bash
npm run phaseone -- canary sign
npm run phaseone -- canary verify
npm run phaseone -- canary list
```

Rotation re-signs and stores `signature_prev` for chain continuity.

## API

- `GET /v1/phaseone/canaries/verify`
- `POST /v1/phaseone/canaries/sign`

Verification is **warn-oriented** — invalid signatures do not block gateway startup.

## SIEM

ECS-ish export includes `phaseone.canary_signature` when present on event metadata.
