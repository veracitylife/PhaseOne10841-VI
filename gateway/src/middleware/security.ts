/**
 * Defensive gateway middleware — security headers + request id.
 * No exploit logic.
 */
import type { MiddlewareHandler } from 'hono';
import { randomBytes } from 'node:crypto';

export const requestIdMiddleware: MiddlewareHandler = async (c, next) => {
  const incoming = c.req.header('x-request-id') ?? c.req.header('x-phaseone-request-id');
  const id = incoming && /^[A-Za-z0-9._-]{8,64}$/.test(incoming) ? incoming : randomBytes(8).toString('hex');
  c.set('requestId' as never, id);
  c.header('X-Request-Id', id);
  c.header('X-PhaseOne-Product', 'PhaseOne10841');
  c.header('X-PhaseOne-Vendor', 'Veracity Integrity LLC');
  await next();
};

export const securityHeadersMiddleware: MiddlewareHandler = async (c, next) => {
  await next();
  c.header('X-Content-Type-Options', 'nosniff');
  c.header('X-Frame-Options', 'DENY');
  c.header('Referrer-Policy', 'no-referrer');
  c.header('X-PhaseOne-Site', 'https://VeracityIntegrity.com');
  // Avoid caching sensitive admin/API responses by default
  if (c.req.path.startsWith('/v1/phaseone')) {
    c.header('Cache-Control', 'no-store');
  }
};

export function registerGatewayMiddleware(app: {
  use: (path: string, ...handlers: MiddlewareHandler[]) => unknown;
}): void {
  app.use('*', requestIdMiddleware);
  app.use('*', securityHeadersMiddleware);
}
