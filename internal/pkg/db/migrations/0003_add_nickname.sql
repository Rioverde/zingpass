-- +goose Up
ALTER TABLE users ADD COLUMN nickname TEXT;
-- Case-insensitive uniqueness; NULL is allowed (existing rows) and multiple NULLs do not collide.
CREATE UNIQUE INDEX users_nickname_lower_idx ON users (LOWER(nickname));

-- +goose Down
DROP INDEX IF EXISTS users_nickname_lower_idx;
ALTER TABLE users DROP COLUMN IF EXISTS nickname;
