-- DROP TABLE IF EXISTS users;
-- CREATE TABLE users (
--     id bigserial PRIMARY KEY,
--     created_at timestamp(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
--     username text NOT NULL,
--     email VARCHAR (255) NOT NULL,
--     password_hash bytea NOT NULL,
--     activated bool NOT NULL,
--     version integer NOT NULL DEFAULT 1
-- );

-- DROP TABLE IF EXISTS tokens;

-- CREATE TABLE tokens (
--     hash bytea PRIMARY KEY,
--     user_id bigint NOT NULL REFERENCES users ON DELETE CASCADE,
--     expiry timestamp(0) WITH TIME ZONE NOT NULL,
--     scope text NOT NULL
-- );