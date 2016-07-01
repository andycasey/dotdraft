
# heroku config -s | grep DATABASE_URL
# psql $DATABASE_URL

DROP TABLE IF EXISTS oauth_states;
CREATE TABLE oauth_states (
    state char(1024) not null,
    ip_address inet not null,
    created timestamp without time zone
);
ALTER TABLE oauth_states ALTER created SET default now();


DROP TABLE IF EXISTS users;
CREATE TABLE users (
    email char(250) not null,
    access_token char(40) not null,
    scope char(120) not null,
    created timestamp without time zone not null
);
ALTER TABLE users ALTER created SET default now();