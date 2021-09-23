"""Normalize PGP key table

Revision ID: c104be7c6187
Revises: 3261793eae54
Create Date: 2021-09-23 11:26:03.551332

"""

# revision identifiers, used by Alembic.
revision = 'c104be7c6187'
down_revision = '3261793eae54'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.execute("""
    ALTER TABLE pgpkey
        RENAME COLUMN key_id TO fingerprint;
    ALTER TABLE pgpkey
        ALTER COLUMN fingerprint TYPE bytea USING decode(fingerprint, 'hex'),
        ALTER COLUMN fingerprint SET NOT NULL,
        ALTER COLUMN key SET NOT NULL,
        DROP COLUMN email,
        ADD CONSTRAINT ix_pgpkey_fingerprint UNIQUE (fingerprint);
    """)


def downgrade():
    op.execute("""
    ALTER TABLE pgpkey
        RENAME COLUMN fingerprint TO key_id;
    ALTER TABLE pgpkey
        ALTER COLUMN key_id TYPE varchar USING encode(key_id, 'hex'),
        ALTER COLUMN key_id DROP NOT NULL,
        ALTER COLUMN key DROP NOT NULL,
        ADD COLUMN email character varying(256),
        DROP CONSTRAINT ix_pgpkey_fingerprint;
    """)
