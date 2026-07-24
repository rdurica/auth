-- name: CreateRefreshToken :one
INSERT INTO auth_refresh_tokens (user_uuid, token, issued_at, expires_at)
VALUES ($1, $2, $3, $4)
RETURNING id;

-- name: GetRefreshTokenByToken :one
SELECT id, user_uuid, token, issued_at, expires_at, revoked_at
FROM auth_refresh_tokens
WHERE token = $1;

-- name: GetActiveRefreshTokenByUser :one
SELECT id, user_uuid, token, issued_at, expires_at, revoked_at
FROM auth_refresh_tokens
WHERE user_uuid = $1 AND revoked_at IS NULL AND expires_at > $2
ORDER BY issued_at DESC
LIMIT 1;

-- name: RevokeRefreshToken :exec
UPDATE auth_refresh_tokens
SET revoked_at = $2
WHERE id = $1 AND revoked_at IS NULL;

-- name: RevokeAllRefreshTokensForUser :exec
UPDATE auth_refresh_tokens
SET revoked_at = $2
WHERE user_uuid = $1 AND revoked_at IS NULL;
