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

    CREATE TABLE gql_profile_wh_sub (
        id serial PRIMARY KEY,
        created timestamp NOT NULL,
        events webhook_event[] NOT NULL CHECK (array_length(events, 1) > 0),
        url varchar NOT NULL,
        query varchar NOT NULL,

        token_hash varchar(128) NOT NULL,
        grants varchar NOT NULL,
        client_id uuid,
        expires timestamp,

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
    DROP TYPE webhook_event;
    """)
