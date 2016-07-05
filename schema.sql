
# heroku config -s | grep DATABASE_URL
# psql $DATABASE_URL

DROP TABLE IF EXISTS oauth_states;
CREATE TABLE oauth_states (
    state char(1024) not null,
    ip_address inet not null,
    created timestamp without time zone
);
ALTER TABLE oauth_states ALTER created SET default now();
ALTER TABLE oauth_states ADD CONSTRAINT unique_state UNIQUE (state);

DROP TABLE IF EXISTS users;
CREATE TABLE users (
    email char(250) not null,
    token char(40) not null,
    scope char(120) not null,
    created timestamp without time zone not null,
    last_sync timestamp without time zone not null

);
ALTER TABLE users ALTER created SET default now();
ALTER TABLE users ADD CONSTRAINT unique_email UNIQUE (email);
ALTER TABLE users ADD COLUMN id BIGSERIAL PRIMARY KEY;


DROP TABLE IF EXISTS repos;
CREATE TABLE repos (
    id integer not null,
    user_id integer not null,
    name char(250) not null,
    hook_id integer default 0
);
ALTER TABLE repos ADD CONSTRAINT unique_repo_id UNIQUE (id);


DROP TABLE IF EXISTS builds;
CREATE TABLE builds (
    user_id integer not null,
    repo_id integer not null,
    state character(7),
    stdout text,
    stderr text,
    pdf bytea
);
ALTER TABLE builds ADD COLUMN id BIGSERIAL PRIMARY KEY;