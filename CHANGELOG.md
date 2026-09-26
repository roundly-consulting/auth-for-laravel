# Changelog

All notable changes to `auth-for-laravel` will be documented in this file.

## Unreleased

### Added

- Multi-guard configuration (`authentication.defaults` + per-guard overrides, lists replace)
  with validation at resolution and the `authentication:check` doctor.
- Password, magic-link, email-code and passwordless passkey login.
- The login challenge engine: TOTP / recovery-code and passkey second factors, forced TOTP and
  passkey enrolment, device binding, attempt limits, supersession and single-use finalization.
- Access tokens (jwt-for-laravel, per-guard audience, `sid` / `amr` / `auth_time`) and rotating
  refresh tokens with device sessions; logout current / one / others / everywhere; the
  invalidation policy with re-issued pairs for the acting device.
- Registration (open / invite-only / closed) and invitations; email verification (link or code)
  and verified email change; forgot / reset / change / set password with a policy and an
  optional k-anonymity breached-password check.
- Re-authentication ("sudo mode") with the strength rule for accounts with a second factor.
- Login activity, throttling, opt-in lockout, new-device detection and risk hooks.
- 42 events, 18 localizable notifications (after-response or encrypted-queue delivery),
  opt-in JSON routes, six middleware, five commands and host testing helpers.
