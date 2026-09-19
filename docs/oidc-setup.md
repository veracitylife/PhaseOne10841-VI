# PhaseOne10841 OIDC/SSO Setup Guide

**Veracity Integrity LLC** · https://VeracityIntegrity.com  
PhaseOne10841 v0.1.2

---

## Overview

PhaseOne10841 supports enterprise Single Sign-On (SSO) via OpenID Connect (OIDC). This enables authentication through identity providers like:

- **Okta**
- **Azure Active Directory (Entra ID)**
- **Auth0**
- **Google Workspace**
- **Keycloak**
- **Any OIDC-compliant provider**

OIDC authentication is **optional** and runs alongside email OTP MFA. You can configure either or both methods.

---

## Environment Variables

Configure OIDC via `PHASEONE_OIDC_*` environment variables in your `.env` file or Docker Compose.

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `PHASEONE_OIDC_ENABLED` | Enable OIDC authentication | `true` |
| `PHASEONE_OIDC_ISSUER` | OIDC issuer URL (provider's base URL) | `https://your-tenant.okta.com` |
| `PHASEONE_OIDC_CLIENT_ID` | OAuth client ID from your IdP | `0oa1b2c3d4e5f6g7h8i9` |
| `PHASEONE_OIDC_CLIENT_SECRET` | OAuth client secret | `your-client-secret` |
| `PHASEONE_OIDC_REDIRECT_URI` | Callback URL (your dashboard URL + `/api/auth/oidc/callback`) | `https://phaseone.example.com/api/auth/oidc/callback` |

### Optional Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PHASEONE_OIDC_SCOPES` | OAuth scopes (space or comma separated) | `openid email profile` |
| `PHASEONE_OIDC_USE_PKCE` | Enable PKCE for enhanced security | `true` |
| `PHASEONE_OIDC_SSO_ONLY` | Disable email OTP when OIDC is configured | `false` |
| `PHASEONE_OIDC_ROLE_CLAIM` | Claim name containing roles/groups | `groups` |
| `PHASEONE_OIDC_ROLE_MAPPING` | JSON mapping of IdP roles to PhaseOne roles | `{"admin":"phaseone-admin"}` |
| `PHASEONE_OIDC_DEFAULT_ROLE` | Default role if no mapping matches | `viewer` |
| `PHASEONE_OIDC_STATE_TTL_MS` | State parameter TTL in milliseconds | `600000` (10 min) |

### Endpoint Overrides (usually auto-discovered)

| Variable | Description |
|----------|-------------|
| `PHASEONE_OIDC_AUTH_ENDPOINT` | Authorization endpoint override |
| `PHASEONE_OIDC_TOKEN_ENDPOINT` | Token endpoint override |
| `PHASEONE_OIDC_USERINFO_ENDPOINT` | Userinfo endpoint override |
| `PHASEONE_OIDC_END_SESSION_ENDPOINT` | Logout endpoint override |
| `PHASEONE_OIDC_JWKS_URI` | JWKS URI for token validation |

---

## Provider Setup Guides

### Okta

1. **Create an OIDC Application**
   - Go to **Applications** → **Create App Integration**
   - Select **OIDC - OpenID Connect** and **Web Application**
   - Name: `PhaseOne10841`

2. **Configure Sign-in Redirect URIs**
   ```
   https://phaseone.example.com/api/auth/oidc/callback
   ```

3. **Configure Sign-out Redirect URIs (optional)**
   ```
   https://phaseone.example.com/
   ```

4. **Assignments**
   - Assign users or groups who should access PhaseOne

5. **Get Credentials**
   - Copy **Client ID** and **Client Secret**
   - Note your Okta domain: `https://your-tenant.okta.com`

6. **PhaseOne Configuration**
   ```bash
   PHASEONE_OIDC_ENABLED=true
   PHASEONE_OIDC_ISSUER=https://your-tenant.okta.com
   PHASEONE_OIDC_CLIENT_ID=0oa1b2c3d4e5f6g7h8i9
   PHASEONE_OIDC_CLIENT_SECRET=your-client-secret
   PHASEONE_OIDC_REDIRECT_URI=https://phaseone.example.com/api/auth/oidc/callback
   PHASEONE_OIDC_ROLE_CLAIM=groups
   PHASEONE_OIDC_ROLE_MAPPING={"admin":"PhaseOne-Admins","viewer":"PhaseOne-Viewers"}
   ```

### Azure Active Directory (Entra ID)

1. **Register an Application**
   - Go to **Azure Portal** → **Microsoft Entra ID** → **App registrations**
   - Click **New registration**
   - Name: `PhaseOne10841`
   - Supported account types: Choose based on your organization
   - Redirect URI: `Web` → `https://phaseone.example.com/api/auth/oidc/callback`

2. **Configure Authentication**
   - Go to **Authentication** tab
   - Enable **ID tokens** under Implicit grant
   - Add front-channel logout URL if needed

3. **Create Client Secret**
   - Go to **Certificates & secrets**
   - Create a new client secret
   - Copy the secret value immediately

4. **Configure Token Claims (for role-based access)**
   - Go to **Token configuration**
   - Add optional claims for `groups` or create app roles

5. **Get Configuration**
   - **Client ID**: From Overview page
   - **Tenant ID**: From Overview page
   - **Issuer**: `https://login.microsoftonline.com/{tenant-id}/v2.0`

6. **PhaseOne Configuration**
   ```bash
   PHASEONE_OIDC_ENABLED=true
   PHASEONE_OIDC_ISSUER=https://login.microsoftonline.com/{tenant-id}/v2.0
   PHASEONE_OIDC_CLIENT_ID=your-client-id
   PHASEONE_OIDC_CLIENT_SECRET=your-client-secret
   PHASEONE_OIDC_REDIRECT_URI=https://phaseone.example.com/api/auth/oidc/callback
   PHASEONE_OIDC_SCOPES=openid email profile
   PHASEONE_OIDC_ROLE_CLAIM=roles
   PHASEONE_OIDC_ROLE_MAPPING={"admin":"PhaseOne.Admin","viewer":"PhaseOne.Viewer"}
   ```

### Auth0

1. **Create an Application**
   - Go to **Applications** → **Create Application**
   - Choose **Regular Web Applications**
   - Name: `PhaseOne10841`

2. **Configure Application**
   - **Allowed Callback URLs**:
     ```
     https://phaseone.example.com/api/auth/oidc/callback
     ```
   - **Allowed Logout URLs**:
     ```
     https://phaseone.example.com/
     ```

3. **Enable Connections**
   - Enable database or social connections as needed

4. **Configure Roles (optional)**
   - Go to **User Management** → **Roles**
   - Create `phaseone-admin` and `phaseone-viewer` roles
   - Use Auth0 Actions or Rules to add roles to tokens

5. **PhaseOne Configuration**
   ```bash
   PHASEONE_OIDC_ENABLED=true
   PHASEONE_OIDC_ISSUER=https://your-tenant.auth0.com/
   PHASEONE_OIDC_CLIENT_ID=your-client-id
   PHASEONE_OIDC_CLIENT_SECRET=your-client-secret
   PHASEONE_OIDC_REDIRECT_URI=https://phaseone.example.com/api/auth/oidc/callback
   PHASEONE_OIDC_SCOPES=openid email profile
   PHASEONE_OIDC_ROLE_CLAIM=https://phaseone.example.com/roles
   ```

---

## Role Mapping

PhaseOne maps IdP claims to two roles: **admin** (full access) and **viewer** (read-only).

### How Role Resolution Works

1. **Check IdP claims** - Look for roles/groups in the configured claim (`PHASEONE_OIDC_ROLE_CLAIM`)
2. **Apply mapping** - Match against `PHASEONE_OIDC_ROLE_MAPPING`
3. **Check email allowlist** - If not SSO-only mode, check `PHASEONE_ADMIN_EMAILS`/`PHASEONE_VIEWER_EMAILS`
4. **Apply default** - Use `PHASEONE_OIDC_DEFAULT_ROLE` if no match

### Example Role Mapping

```bash
# Map IdP groups to PhaseOne roles
PHASEONE_OIDC_ROLE_MAPPING={"admin":"SecurityTeam-Admins","viewer":"SecurityTeam-Viewers"}
```

The JSON maps PhaseOne roles (keys) to IdP group/role names (values).

### SSO-Only Mode

When `PHASEONE_OIDC_SSO_ONLY=true`:
- Email OTP authentication is disabled
- Only OIDC authentication is available
- Email allowlist (`PHASEONE_ADMIN_EMAILS`) is bypassed
- Roles are determined solely by IdP claims

---

## Security Considerations

### PKCE

PKCE (Proof Key for Code Exchange) is enabled by default for enhanced security. It protects against authorization code interception attacks. Disable only if your IdP doesn't support it:

```bash
PHASEONE_OIDC_USE_PKCE=false
```

### Client Secret Protection

- Never commit `PHASEONE_OIDC_CLIENT_SECRET` to version control
- Use environment variables or secrets management
- Rotate secrets periodically

### Redirect URI Validation

- Configure exact redirect URIs in your IdP (no wildcards)
- Use HTTPS in production
- Match the URI exactly with `PHASEONE_OIDC_REDIRECT_URI`

### Session Security

OIDC sessions inherit PhaseOne's security settings:
- Session TTL: `PHASEONE_SESSION_TTL_MS` (default 8 hours)
- Secure cookies: `PHASEONE_SECURE_COOKIES=true` for HTTPS
- CSRF protection: Automatic with session tokens

---

## Troubleshooting

### "Invalid or expired state parameter"

- State TTL may be too short; increase `PHASEONE_OIDC_STATE_TTL_MS`
- User took too long to authenticate
- Browser may have cached old state

### "No email found in IdP response"

- Ensure `email` scope is requested
- Check IdP application permissions
- Verify user has email attribute set

### "Token audience does not match client_id"

- Client ID mismatch between PhaseOne and IdP
- Check for typos in `PHASEONE_OIDC_CLIENT_ID`
- Some IdPs use different audience values; check IdP documentation

### Discovery Endpoint Not Found

If auto-discovery fails, manually specify endpoints:

```bash
PHASEONE_OIDC_AUTH_ENDPOINT=https://your-idp.com/oauth/authorize
PHASEONE_OIDC_TOKEN_ENDPOINT=https://your-idp.com/oauth/token
PHASEONE_OIDC_USERINFO_ENDPOINT=https://your-idp.com/userinfo
```

### Debug Mode

Enable test mode for debugging (development only):

```bash
PHASEONE_AUTH_TEST_MODE=true
```

Check dashboard console and server logs for detailed OIDC flow information.

---

## Example Complete Configuration

```bash
# .env file

# OIDC/SSO Configuration
PHASEONE_OIDC_ENABLED=true
PHASEONE_OIDC_ISSUER=https://your-tenant.okta.com
PHASEONE_OIDC_CLIENT_ID=0oa1b2c3d4e5f6g7h8i9
PHASEONE_OIDC_CLIENT_SECRET=your-client-secret
PHASEONE_OIDC_REDIRECT_URI=https://phaseone.example.com/api/auth/oidc/callback
PHASEONE_OIDC_SCOPES=openid email profile groups
PHASEONE_OIDC_USE_PKCE=true
PHASEONE_OIDC_SSO_ONLY=false
PHASEONE_OIDC_ROLE_CLAIM=groups
PHASEONE_OIDC_ROLE_MAPPING={"admin":"PhaseOne-Admins","viewer":"PhaseOne-Viewers"}
PHASEONE_OIDC_DEFAULT_ROLE=viewer

# Keep email OTP as fallback
PHASEONE_ADMIN_EMAILS=admin@example.com,security@example.com
PHASEONE_VIEWER_EMAILS=analyst@example.com

# Session security
PHASEONE_SECURE_COOKIES=true
PHASEONE_SESSION_TTL_MS=28800000
```

---

## Testing OIDC Integration

1. **Verify Configuration**
   ```bash
   curl -s http://localhost:3000/api/auth/status | jq .oidc
   ```

2. **Test SSO Login Flow**
   - Open dashboard in browser
   - Click "Sign in with SSO"
   - Complete authentication in IdP
   - Verify redirect back to dashboard with active session

3. **Test Logout Flow**
   - Click "Logout" in dashboard
   - Verify redirect to IdP logout (if configured)
   - Verify session is cleared

---

**DEFENSIVE ONLY** — PhaseOne10841 is a defensive security gateway.  
Contact Veracity Integrity LLC via https://VeracityIntegrity.com for support.
