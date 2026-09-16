/**
 * Inert fake-web stub — returns static pages for detector testing.
 * No real crawling, no exploitation.
 */

import { BENIGN_SAMPLES, INJECTION_FIXTURES, FIXTURE_LABEL } from '../fixtures/injection-markers.js';

export interface FakeWebPage {
  url: string;
  title: string;
  body: string;
  fixture?: boolean;
}

const PAGES: FakeWebPage[] = [
  {
    url: 'https://lab.phaseone.test/docs/pto',
    title: 'PTO Policy',
    body: BENIGN_SAMPLES.find((s) => s.id === 'benign.rag')!.text,
    fixture: false,
  },
  {
    url: 'https://lab.phaseone.test/fixture/injection-web',
    title: `${FIXTURE_LABEL} web page`,
    body: INJECTION_FIXTURES.find((f) => f.id === 'fixture.ignore_previous')!.text,
    fixture: true,
  },
  {
    url: 'https://lab.phaseone.test/fixture/hidden-markers',
    title: `${FIXTURE_LABEL} hidden markers`,
    body: INJECTION_FIXTURES.find((f) => f.id === 'fixture.hidden_markers')!.text,
    fixture: true,
  },
];

export function fetchPage(url: string, opts?: { allowFixtures?: boolean }): FakeWebPage | null {
  const page = PAGES.find((p) => p.url === url);
  if (!page) return null;
  if (page.fixture && !opts?.allowFixtures) {
    return {
      url: page.url,
      title: 'Fixture disabled',
      body: 'Fixture content suppressed. Pass allowFixtures=true for detector tests.',
      fixture: true,
    };
  }
  return page;
}

export function listPages(): Array<{ url: string; fixture?: boolean }> {
  return PAGES.map((p) => ({ url: p.url, fixture: p.fixture }));
}
