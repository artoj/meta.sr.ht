"""Add comment to oauthtoken

Revision ID: db18bd34de5a
Revises: '6cdf6b9f90a2'
Create Date: 2020-09-02 13:48:09.098431

"""

# revision identifiers, used by Alembic.
revision = 'db18bd34de5a'
down_revision = '6cdf6b9f90a2'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('oauthtoken', sa.Column('comment', sa.String(128)))


def downgrade():
    op.drop_column('oauthtoken', 'comment')
