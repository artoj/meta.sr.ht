"""Add welcome emails counter to users

Revision ID: f1f6b32242fe
Revises: 262b6b422637
Create Date: 2018-11-16 09:45:46.780305

"""

# revision identifiers, used by Alembic.
revision = 'f1f6b32242fe'
down_revision = '262b6b422637'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('user', sa.Column('welcome_emails',
        sa.Integer, nullable=False, server_default='0'))


def downgrade():
    op.drop_column('user', 'welcome_emails')
