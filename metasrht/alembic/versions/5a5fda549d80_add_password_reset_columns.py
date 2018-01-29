"""Add password reset columns

Revision ID: 5a5fda549d80
Revises: da70e75bc1a4
Create Date: 2018-01-28 22:23:28.589944

"""

# revision identifiers, used by Alembic.
revision = '5a5fda549d80'
down_revision = 'da70e75bc1a4'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('user', sa.Column('reset_hash', sa.String(128)))
    op.add_column('user', sa.Column('reset_expiry', sa.DateTime()))


def downgrade():
    op.drop_column('user', 'reset_hash')
    op.drop_column('user', 'reset_expiry')
