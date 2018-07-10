"""Expand maximum size of PGP keys

Revision ID: 9caaf5055676
Revises: 839e4a29751a
Create Date: 2018-07-10 08:29:15.686334

"""

# revision identifiers, used by Alembic.
revision = '9caaf5055676'
down_revision = '839e4a29751a'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.alter_column('pgpkey', 'key', type_=sa.String(32768))


def downgrade():
    op.alter_column('pgpkey', 'key', type_=sa.String(16384))
