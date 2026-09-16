# PhaseOne10841 Lab (defensive)

Inert stubs + labeled TEST fixtures for detector verification.

## What this is

- `stubs/` — fake-email, fake-web, fake-mcp, fake-rag returning benign content
- `fixtures/injection-markers.ts` — clearly marked `PHASEONE_TEST_INJECTION_*` strings
- `monitor.ts` — asserts scanners fire on fixtures and stay quiet on benign samples

## What this is NOT

- No real exploitation, credential theft tooling, or privilege-escalation scripts
- No Daybreak / offensive attack simulator payloads
- Fixtures are detector true-positive samples, not weaponized playbooks

## Run

```bash
npx tsx lab/index.ts
npm test -- tests/lab-detectors.test.ts
```
