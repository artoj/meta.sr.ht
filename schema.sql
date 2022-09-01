CREATE TYPE auth_method AS ENUM (
	'OAUTH_LEGACY',
	'OAUTH2',
	'COOKIE',
	'INTERNAL',
	'WEBHOOK'
);

CREATE TYPE webhook_event AS ENUM (
	'PROFILE_UPDATE',
	'PGP_KEY_ADDED',
	'PGP_KEY_REMOVED',
	'SSH_KEY_ADDED',
	'SSH_KEY_REMOVED'
);

CREATE TABLE "user" (
	id serial PRIMARY KEY,
	created timestamp without time zone NOT NULL,
	updated timestamp without time zone NOT NULL,
	username character varying(256) NOT NULL,
	password character varying(256) NOT NULL,
	email character varying(256) NOT NULL,
	new_email character varying(256),
	user_type character varying NOT NULL,
	confirmation_hash character varying(128),
	url character varying(256),
	location character varying(256),
	bio character varying(4096),
	pgp_key_id integer,
	reset_hash character varying(128),
	reset_expiry timestamp without time zone,
	invites integer DEFAULT 0,
	stripe_customer character varying(256),
	payment_cents integer DEFAULT 0 NOT NULL,
	payment_interval character varying DEFAULT 'monthly'::character varying,
	payment_due timestamp without time zone,
	welcome_emails integer DEFAULT 0 NOT NULL,
	oauth_revocation_token character varying(256),
	suspension_notice character varying(4096),
	CONSTRAINT user_username_unique UNIQUE (username),
	CONSTRAINT user_email_unique UNIQUE (email)
);

CREATE INDEX ix_user_username ON "user" USING btree (username);

CREATE TABLE audit_log_entry (
	id serial PRIMARY KEY,
	created timestamp without time zone NOT NULL,
	user_id integer NOT NULL REFERENCES "user"(id),
	ip_address character varying(50) NOT NULL,
	event_type character varying(256) NOT NULL,
	details character varying(512)
);

CREATE TABLE invite (
	id serial PRIMARY KEY,
	created timestamp without time zone NOT NULL,
	updated timestamp without time zone NOT NULL,
	invite_hash character varying(128),
	sender_id integer,
	recipient_id integer
);

CREATE TABLE invoice (
	id serial PRIMARY KEY,
	created timestamp without time zone NOT NULL,
	updated timestamp without time zone NOT NULL,
	cents integer NOT NULL,
	user_id integer NOT NULL REFERENCES "user"(id),
	valid_thru timestamp without time zone NOT NULL,
	source character varying(256) NOT NULL
);

CREATE TABLE pgpkey (
	id serial PRIMARY KEY,
	created timestamp without time zone,
	user_id integer REFERENCES "user"(id),
	key character varying(32768) NOT NULL,
	fingerprint bytea NOT NULL UNIQUE,
	expiration timestamp without time zone
);

ALTER TABLE "user"
	ADD CONSTRAINT user_pgp_key_id_fkey
	FOREIGN KEY (pgp_key_id) REFERENCES pgpkey(id);

CREATE TABLE sshkey (
	id serial PRIMARY KEY,
	created timestamp without time zone,
	user_id integer REFERENCES "user"(id),
	key character varying(4096) NOT NULL,
	fingerprint character varying(512) NOT NULL UNIQUE,
	comment character varying(256),
	last_used timestamp without time zone,
	b64_key character varying(4096),
	key_type character varying(256)
);

CREATE INDEX key_index ON sshkey USING btree (md5((key)::text));

CREATE TABLE user_auth_factor (
	id serial PRIMARY KEY,
	user_id integer NOT NULL UNIQUE REFERENCES "user"(id),
	created timestamp without time zone NOT NULL,
	updated timestamp without time zone NOT NULL,
	factor_type character varying NOT NULL,
	secret bytea,
	extra json
);

CREATE TABLE user_notes (
	id serial PRIMARY KEY,
	created timestamp without time zone NOT NULL,
	user_id integer NOT NULL REFERENCES "user"(id),
	note character varying
);

-- OAuth 2.0
CREATE TABLE oauth2_client (
	id serial PRIMARY KEY,
	created timestamp without time zone NOT NULL,
	updated timestamp without time zone NOT NULL,
	owner_id integer NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
	client_uuid uuid NOT NULL,
	client_secret_hash character varying(128) NOT NULL,
	client_secret_partial character varying(8) NOT NULL,
	redirect_url character varying,
	client_name character varying(256) NOT NULL,
	client_description character varying,
	client_url character varying,
	revoked boolean DEFAULT false NOT NULL
);

CREATE TABLE oauth2_grant (
	id serial PRIMARY KEY,
	issued timestamp without time zone NOT NULL,
	expires timestamp without time zone NOT NULL,
	comment character varying,
	token_hash character varying(128) NOT NULL,
	user_id integer NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
	client_id integer REFERENCES oauth2_client(id) ON DELETE CASCADE
);

-- GraphQL webhooks
CREATE TABLE gql_profile_wh_sub (
	id serial PRIMARY KEY,
	created timestamp without time zone NOT NULL,
	events webhook_event[] NOT NULL,
	url character varying NOT NULL,
	query character varying NOT NULL,
	auth_method auth_method NOT NULL,
	token_hash character varying(128),
	grants character varying,
	client_id uuid,
	expires timestamp without time zone,
	node_id character varying,
	user_id integer NOT NULL REFERENCES "user"(id),
	CONSTRAINT gql_profile_wh_sub_auth_method_check
		CHECK ((auth_method = ANY(ARRAY['OAUTH2'::auth_method, 'INTERNAL'::auth_method]))),
	CONSTRAINT gql_profile_wh_sub_check
		CHECK (((auth_method = 'OAUTH2'::auth_method) = (token_hash IS NOT NULL))),
	CONSTRAINT gql_profile_wh_sub_check1
		CHECK (((auth_method = 'OAUTH2'::auth_method) = (expires IS NOT NULL))),
	CONSTRAINT gql_profile_wh_sub_check2
		CHECK (((auth_method = 'INTERNAL'::auth_method) = (node_id IS NOT NULL))),
	CONSTRAINT gql_profile_wh_sub_events_check
		CHECK ((array_length(events, 1) > 0))
);

CREATE INDEX gql_profile_wh_sub_token_hash_idx ON gql_profile_wh_sub USING btree (token_hash);

CREATE TABLE gql_profile_wh_delivery (
	id serial PRIMARY KEY,
	uuid uuid NOT NULL,
	date timestamp without time zone NOT NULL,
	event webhook_event NOT NULL,
	subscription_id integer NOT NULL
		REFERENCES gql_profile_wh_sub(id) ON DELETE CASCADE,
	request_body character varying NOT NULL,
	response_body character varying,
	response_headers character varying,
	response_status integer
);

-- Legacy OAuth (TODO: Remove these)
CREATE TABLE oauthclient (
	id serial PRIMARY KEY,
	created timestamp without time zone NOT NULL,
	updated timestamp without time zone NOT NULL,
	user_id integer REFERENCES "user"(id),
	client_name character varying(256) NOT NULL,
	client_id character varying(16) NOT NULL,
	client_secret_hash character varying(128) NOT NULL,
	client_secret_partial character varying(8) NOT NULL,
	redirect_uri character varying(256),
	preauthorized boolean DEFAULT false NOT NULL
);

CREATE TABLE oauthscope (
	id serial PRIMARY KEY,
	created timestamp without time zone NOT NULL,
	updated timestamp without time zone NOT NULL,
	client_id integer NOT NULL REFERENCES oauthclient(id),
	name character varying(256) NOT NULL,
	description character varying(512) NOT NULL,
	write boolean NOT NULL
);

CREATE TABLE oauthtoken (
	id serial PRIMARY KEY,
	created timestamp without time zone NOT NULL,
	updated timestamp without time zone NOT NULL,
	expires timestamp without time zone NOT NULL,
	user_id integer REFERENCES "user"(id),
	client_id integer REFERENCES oauthclient(id) ON DELETE CASCADE,
	token_hash character varying(128) NOT NULL,
	token_partial character varying(8) NOT NULL,
	scopes character varying(512) NOT NULL,
	comment character varying(128)
);

CREATE TABLE revocationurl (
	id serial PRIMARY KEY,
	created timestamp without time zone NOT NULL,
	updated timestamp without time zone NOT NULL,
	token_id integer NOT NULL REFERENCES oauthtoken(id),
	client_id integer NOT NULL REFERENCES oauthclient(id),
	url character varying(2048) NOT NULL
);

CREATE TABLE delegatedscope (
	id serial PRIMARY KEY,
	created timestamp without time zone NOT NULL,
	updated timestamp without time zone NOT NULL,
	client_id integer NOT NULL REFERENCES oauthclient(id) ON DELETE CASCADE,
	name character varying(256) NOT NULL,
	description character varying(512) NOT NULL,
	write boolean NOT NULL
);

-- Legacy webhooks (TODO: Remove these)
CREATE TABLE user_webhook_subscription (
	id serial PRIMARY KEY,
	created timestamp without time zone NOT NULL,
	url character varying(2048) NOT NULL,
	events character varying NOT NULL,
	user_id integer REFERENCES "user"(id),
	token_id integer REFERENCES oauthtoken(id)
);

CREATE TABLE user_webhook_delivery (
	id serial PRIMARY KEY,
	uuid uuid NOT NULL,
	created timestamp without time zone NOT NULL,
	event character varying(256) NOT NULL,
	url character varying(2048) NOT NULL,
	payload character varying(16384) NOT NULL,
	payload_headers character varying(16384) NOT NULL,
	response character varying(16384),
	response_status integer NOT NULL,
	response_headers character varying(16384),
	subscription_id integer REFERENCES user_webhook_subscription(id)
);

CREATE TABLE webhook_subscription (
	id serial PRIMARY KEY,
	created timestamp without time zone NOT NULL,
	url character varying(2048) NOT NULL,
	events character varying NOT NULL,
	user_id integer REFERENCES "user"(id) ON DELETE CASCADE,
	client_id integer REFERENCES oauthclient(id) ON DELETE CASCADE
);
