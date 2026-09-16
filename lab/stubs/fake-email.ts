/**
 * Inert fake-email stub — returns benign content or optional TEST injection fixtures.
 * No real SMTP, no credential theft, no delivery.
 */

import { BENIGN_SAMPLES, INJECTION_FIXTURES, FIXTURE_LABEL } from '../fixtures/injection-markers.js';

export interface FakeEmailMessage {
  id: string;
  from: string;
  subject: string;
  body: string;
  fixture?: boolean;
}

export function listInbox(opts?: { includeFixtures?: boolean }): FakeEmailMessage[] {
  const msgs: FakeEmailMessage[] = [
    {
      id: 'mail-1',
      from: 'noreply@example.invalid',
      subject: 'Meeting notes',
      body: BENIGN_SAMPLES.find((s) => s.id === 'benign.email')!.text,
      fixture: false,
    },
  ];
  if (opts?.includeFixtures) {
    const fix = INJECTION_FIXTURES.find((f) => f.channel === 'email')!;
    msgs.push({
      id: 'mail-fixture-1',
      from: 'fixture@phaseone.test',
      subject: `${FIXTURE_LABEL} detector email`,
      body: fix.text,
      fixture: true,
    });
  }
  return msgs;
}

export function readMessage(id: string, includeFixtures = false): FakeEmailMessage | null {
  return listInbox({ includeFixtures }).find((m) => m.id === id) ?? null;
}
