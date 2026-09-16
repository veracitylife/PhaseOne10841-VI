/**
 * RBAC lite — admin vs viewer by email allowlists.
 * Viewers: read-only. Admins: full mutating dashboard actions.
 */

export type DashboardRole = 'admin' | 'viewer' | 'none';

export interface RbacConfig {
  adminEmails: string[];
  viewerEmails: string[];
  /** When true, empty viewer list means no viewers (admins only). */
  allowAllAdminsWildcard: boolean;
}

export function loadRbacConfig(): RbacConfig {
  const adminEmails = (process.env.PHASEONE_ADMIN_EMAILS ?? process.env.DASHBOARD_ADMIN_EMAILS ?? 'admin@localhost')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  const viewerEmails = (process.env.PHASEONE_VIEWER_EMAILS ?? '')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  return {
    adminEmails,
    viewerEmails,
    allowAllAdminsWildcard: adminEmails.includes('*'),
  };
}

export function resolveRole(emailRaw: string, cfg = loadRbacConfig()): DashboardRole {
  const email = emailRaw.trim().toLowerCase();
  if (!email || !email.includes('@')) return 'none';
  if (cfg.allowAllAdminsWildcard || cfg.adminEmails.includes(email)) return 'admin';
  if (cfg.viewerEmails.includes('*') || cfg.viewerEmails.includes(email)) return 'viewer';
  return 'none';
}

export function canMutate(role: DashboardRole): boolean {
  return role === 'admin';
}

export function canRead(role: DashboardRole): boolean {
  return role === 'admin' || role === 'viewer';
}

export function isAuthorizedEmail(email: string, cfg = loadRbacConfig()): boolean {
  return resolveRole(email, cfg) !== 'none';
}
