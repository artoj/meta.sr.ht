"""add b64_key and key_type options to SSHKey

Revision ID: 6cdf6b9f90a2
Revises: d950ba31b98d
Create Date: 2019-08-14 13:43:26.743795

"""

# revision identifiers, used by Alembic.
revision = '6cdf6b9f90a2'
down_revision = 'd950ba31b98d'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('sshkey', sa.Column('b64_key', sa.String(4096)))
    op.add_column('sshkey', sa.Column('key_type', sa.String(256)))


def downgrade():
    op.drop_column('sshkey', 'b64_key')
    op.drop_column('sshkey', 'key_type')
