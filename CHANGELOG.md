# Changelog

All notable changes to `auth-for-laravel` are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## Unreleased

Initial public release.

### Added

- Headless, multi-guard authentication through the `Authentication` facade: password, magic-link,
  email-code and passwordless passkey login.
- Multi-step login challenges for TOTP or recovery-code second factors, passkey second factors
  and forced two-factor or passkey enrolment.
- RS256 access tokens with rotating refresh tokens and device sessions, including logout of one
  session, all others or everywhere — built on jwt-for-laravel and refresh-tokens-for-laravel.
- Registration and invitations (`register()`, `invite()`, `acceptInvitation()`).
- Email verification and verified email change.
- Forgot, reset and change password with a password policy and an optional breached-password check.
- Per-account locale and time zone, plus re-authentication for sensitive actions.
- Login-activity log with throttling, lockout, new-device detection and risk hooks.
- Opt-in JSON endpoints for every flow, with uniform error codes and route middleware
  (`authentication.verified`, `authentication.reauthenticated`, …).
- 18 mail notifications, swappable per guard, and an event for every state change.
- Artisan commands `authentication:install`, `authentication:guard`, `authentication:check`,
  `authentication:prune` and `authentication:logout-everywhere`.
- `InteractsWithAuthentication` test helpers (`actingAsAccount()` with a real token pair,
  `assertLoginActivity()`, `assertTokensInvalidated()`).
