"""Add constraints to SSH keys

Revision ID: a08050104214
Revises: c104be7c6187
Create Date: 2021-09-23 12:59:37.333080

"""

# revision identifiers, used by Alembic.
revision = 'a08050104214'
down_revision = 'c104be7c6187'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.execute("""
    ALTER TABLE sshkey
    ALTER COLUMN fingerprint SET NOT NULL,
    ALTER COLUMN key SET NOT NULL,
    ADD CONSTRAINT ix_sshkey_fingerprint UNIQUE (fingerprint);
    """)


def downgrade():
    op.execute("""
    ALTER TABLE sshkey
    ALTER COLUMN fingerprint DROP NOT NULL,
    ALTER COLUMN key DROP NOT NULL,
    DROP CONSTRAINT ix_sshkey_fingerprint;
    """)
