"""Add GraphQL webhook tables

Revision ID: 3261793eae54
Revises: 3e4e74262480
Create Date: 2021-07-30 10:05:06.919513

"""

# revision identifiers, used by Alembic.
revision = '3261793eae54'
down_revision = '3e4e74262480'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.execute("""
    CREATE TYPE webhook_event AS ENUM (
        'PROFILE_UPDATE',
        'PGP_KEY_ADDED',
        'PGP_KEY_REMOVED',
        'SSH_KEY_ADDED',
        'SSH_KEY_REMOVED'
    );

    CREATE TYPE auth_method AS ENUM (
        'OAUTH_LEGACY',
        'OAUTH2',
        'COOKIE',
        'INTERNAL',
        'WEBHOOK'
    );

    CREATE TABLE gql_profile_wh_sub (
        id serial PRIMARY KEY,
        created timestamp NOT NULL,
        events webhook_event[] NOT NULL check (array_length(events, 1) > 0),
        url varchar NOT NULL,
        query varchar NOT NULL,

        auth_method auth_method NOT NULL check (auth_method in ('OAUTH2', 'INTERNAL')),
        token_hash varchar(128) check ((auth_method = 'OAUTH2') = (token_hash IS NOT NULL)),
        grants varchar,
        client_id uuid,
        expires timestamp check ((auth_method = 'OAUTH2') = (expires IS NOT NULL)),
        node_id varchar check ((auth_method = 'INTERNAL') = (node_id IS NOT NULL)),

        user_id integer NOT NULL references "user"(id)
    );

    CREATE INDEX gql_profile_wh_sub_token_hash_idx ON gql_profile_wh_sub (token_hash);

    CREATE TABLE gql_profile_wh_delivery (
        id serial PRIMARY KEY,
        uuid uuid NOT NULL,
        date timestamp NOT NULL,
        event webhook_event NOT NULL,
        subscription_id integer NOT NULL references gql_profile_wh_sub(id) ON DELETE CASCADE,
        request_body varchar NOT NULL,
        response_body varchar,
        response_headers varchar,
        response_status integer
    );
    """)


def downgrade():
    op.execute("""
    DROP TABLE gql_profile_wh_delivery;
    DROP INDEX gql_profile_wh_sub_token_hash_idx;
    DROP TABLE gql_profile_wh_sub;
    DROP TYPE auth_method;
    DROP TYPE webhook_event;
    """)
