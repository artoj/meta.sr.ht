"""Add unique constraint to user_auth_factor

Revision ID: 2d417400aa37
Revises: 0972ddb8d4f8
Create Date: 2020-10-05 14:17:00.638364

"""

# revision identifiers, used by Alembic.
revision = '2d417400aa37'
down_revision = '0972ddb8d4f8'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_unique_constraint('uq_user_auth_factor_user_id',
            'user_auth_factor', ['user_id'])


def downgrade():
    op.drop_constraint('uq_user_auth_factor_user_id', 'user_auth_factor')
