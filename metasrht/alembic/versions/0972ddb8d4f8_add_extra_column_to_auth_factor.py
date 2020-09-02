"""Add extra column to auth factor

Revision ID: 0972ddb8d4f8
Revises: db18bd34de5a
Create Date: 2020-09-02 14:08:08.417884

"""

# revision identifiers, used by Alembic.
revision = '0972ddb8d4f8'
down_revision = 'db18bd34de5a'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column("user_auth_factor", sa.Column("extra", sa.JSON))


def downgrade():
    op.drop_column("user_auth_factor", "extra")
