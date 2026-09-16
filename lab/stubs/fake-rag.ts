/**
 * Inert fake-RAG stub — returns retrieved context chunks for scanner tests.
 */

import { BENIGN_SAMPLES, INJECTION_FIXTURES, FIXTURE_LABEL } from '../fixtures/injection-markers.js';

export interface FakeRagChunk {
  id: string;
  source: string;
  text: string;
  fixture?: boolean;
}

export function retrieve(query: string, opts?: { includeFixtures?: boolean }): FakeRagChunk[] {
  const chunks: FakeRagChunk[] = [
    {
      id: 'rag-1',
      source: 'handbook.md',
      text: BENIGN_SAMPLES.find((s) => s.id === 'benign.rag')!.text,
      fixture: false,
    },
  ];
  if (opts?.includeFixtures || /fixture|injection|test/i.test(query)) {
    chunks.push({
      id: 'rag-fixture-1',
      source: `${FIXTURE_LABEL}/poisoned-doc.md`,
      text: INJECTION_FIXTURES.find((f) => f.channel === 'rag')!.text,
      fixture: true,
    });
  }
  return chunks;
}
