# Day 1 acceptance checklist

- [x] Keycloak container starts and imports the `primesoc` realm.
- [x] First SOC user can authenticate through Keycloak.
- [x] Unauthenticated request to `/dashboard` redirects to `/login` (`/` is the public landing page).
- [x] Authenticated user sees dashboard, identity and realm roles. Users with no PrimeSEC role are sent to `/403`.
- [x] Sign-out returns user to login.
- [x] `/api/health` returns HTTP 200.
- [ ] `WAZUH_DASHBOARD_URL` is configured to the correct HTTPS host.
- [ ] Wazuh SAML client and role mapping are configured using the version-matched official guide.
- [ ] Wazuh opens from the PrimeSEC link without a second credential prompt while the Keycloak session is active.
- [ ] Admin and read-only users have distinct Wazuh permissions.
