# Auth

Standalone Go authentication service with JWT (RS256), opaque refresh tokens, email verification, and password reset - built for multi-service backends.

![Go 1.26+](docs/assets/badges/go.svg)
![PostgreSQL](docs/assets/badges/postgresql.svg)
![JWT RS256](docs/assets/badges/jwt.svg)
![Redis](docs/assets/badges/redis.svg)
![argon2id](docs/assets/badges/argon2id.svg)
![License: MIT](docs/assets/badges/license.svg)

<p align="center">
  <img src="docs/assets/logo.png" alt="Auth logo" width="512" />
</p>

## Features

- **JWT access tokens** — RS256-signed, short-lived, with published JWKS for consumers
- **Opaque refresh tokens** — stored in PostgreSQL with rotation near expiry
- **Account lifecycle** — register, login, email verification, password reset
- **Profile API** — authenticated user profile, password change, account deletion
- **Rate limiting** — Redis-backed global API limits plus login brute-force protection (per IP / per email)
- **Dev-friendly mail** — Mailpit / log driver for local verification flows

## Requirements

| Tool | Purpose |
|------|---------|
| [Go](https://go.dev/) 1.26+ | Runtime & toolchain |
| [dev-stack](https://github.com/rdurica/dev-stack) | Local Postgres (`:5432`), Redis (`:6379`), Mailpit SMTP (`:1025`) |
| OpenSSL | JWT key generation |

Database migrations run via `go run` ([goose](https://github.com/pressly/goose)) — no global install required.

## Quick start

Ensure `dev-stack` is running (`postgres` + `redis` + `mailpit`). Redis must expose `localhost:6379`.

```bash
cp .env.example .env   # preconfigured for root:password@localhost:5432 + Mailpit
make setup             # JWT keys + CREATE DATABASE auth + migrations
make run
```

| Service | URL |
|---------|-----|
| API | `http://localhost:8080` |
| Mailpit UI | `https://mail.localhost:8443/` |
| Postgres | `postgres://root:password@localhost:5432/auth` |

## API

### Public

| Method | Path | Body |
|--------|------|------|
| `POST` | `/api/auth/register` | `{email,password,firstName,lastName}` → `201` `{uuid,emailVerificationRequired}` |
| `POST` | `/api/auth/login` | `{email,password}` → `{authenticationToken,refreshToken}` |
| `POST` | `/api/auth/refresh` | `{refreshToken}` → `{authenticationToken}` (+ optional `{refreshToken}`) |
| `POST` | `/api/auth/logout` | `{refreshToken}` → `204` (idempotent revoke) |
| `POST` | `/api/auth/verify-email` | `{token}` → `{verified:true}` |
| `POST` | `/api/auth/verify-email/resend` | `{email}` → `{emailSent:true}` |
| `POST` | `/api/auth/password-reset` | `{email}` → `{emailSent:true}` |
| `POST` | `/api/auth/password-reset/validate` | `{token}` → `{valid:true}` |
| `POST` | `/api/auth/password-reset/confirm` | `{token,password}` → `{passwordChanged:true}` |
| `GET` | `/health` | — |
| `GET` | `/.well-known/jwks.json` | JWKS for JWT consumers |

### Protected (Bearer access JWT)

| Method | Path | Notes |
|--------|------|-------|
| `GET` | `/api/user/profile` | Profile DTO |
| `PATCH` | `/api/user/profile` | Partial update → `{updated:true}` (`PUT` kept as alias) |
| `PUT` | `/api/user/password` | → `{passwordChanged:true}` |
| `DELETE` | `/api/user/account` | Body `{confirmation:"DELETE",password}` → `204` |

Errors use `Content-Type: application/problem+json` with `type`, `code`, `title`, `status`, `detail`, and optionally `errors` / `waitSeconds`. Unknown routes and wrong methods also return problem+json (`not_found` / `method_not_allowed`). Rate-limit responses include `Retry-After` (seconds) plus `X-RateLimit-*` headers. Login lockouts use code `login_rate_limited` (failed attempts only; counters clear for that email after a successful login).

## Auth model

| Concern | Details |
|---------|---------|
| Access JWT | RS256, TTL 1 h (`JWT_TTL_SECONDS`), claim `uuid` |
| Refresh token | 64-hex opaque string, 30 days in DB; rotates when expiry is within 1 h |
| Passwords | argon2id |
| Email verification | 64-hex token, TTL 3 h |
| Password reset | 64-hex token, TTL 1 h |

Login requires both `is_active` and `is_email_verified`.

In development, `MAIL_DRIVER=log` writes emails (including tokens) to stdout.

## Consumer guide

Other services should validate tokens as follows:

1. Fetch JWKS from `GET /.well-known/jwks.json` (or use the public PEM).
2. Validate the JWT: algorithm **RS256**, `exp`, and claim **`uuid`**.
3. Use `uuid` as the stable user identifier in your API.
4. Do not persist access tokens — call `/api/auth/refresh` when they expire.

Example claims:

```json
{
  "uuid": "018f...",
  "roles": ["USER"],
  "iss": "auth",
  "sub": "018f...",
  "iat": 1710000000,
  "exp": 1710003600
}
```

## Configuration

See [`.env.example`](.env.example). Key variables:

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | PostgreSQL connection string |
| `REDIS_URL` | Global API rate limit (60/min anonymous, 300/min authenticated) and login brute-force limits (5 failures / 15 min per email, 20 / 15 min per IP) |
| `JWT_PRIVATE_KEY_PATH` / `JWT_PUBLIC_KEY_PATH` | RSA key pair paths |
| `MAIL_DRIVER` | `log` or `smtp` |
| `WEB_BASE_URL` | Base URL for links in emails |

## Postman

Import [`postman/Auth.postman_collection.json`](postman/Auth.postman_collection.json).

- `baseUrl` defaults to `http://localhost:8080`
- Login / Refresh scripts store tokens in collection variables
- Copy verification / reset tokens from Mailpit into `verificationToken` / `passwordResetToken`

## Development

```bash
make test
make tidy
make sqlc   # after changing SQL under internal/store/postgres/sql/
```

SQL sources live in `internal/store/postgres/sql/`; generated code is in `internal/store/postgres/sqlc/` ([sqlc](https://sqlc.dev)).

## Project layout

Pragmatic DDD: rich aggregates in `domain/`, thin use cases in `app/`, infrastructure outside the domain.

```
cmd/auth/           # entrypoint
internal/
  app/              # use cases (load → domain → save → side effects)
  config/
  domain/           # User / RefreshToken aggregates + value objects
  httpapi/          # HTTP, middleware, problem+json
  mail/
  password/
  ratelimit/        # Redis global + login brute-force limiters
  store/postgres/   # repository adapters + sqlc schema/queries
    sql/            # schema.sql + queries/*.sql (sqlc source of truth)
    sqlc/           # generated code (do not edit)
  token/            # JWT + opaque tokens
migrations/
deploy/compose.yaml
sqlc.yaml
```
