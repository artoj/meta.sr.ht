"""Add notes to users

Revision ID: d950ba31b98d
Revises: cb4742f68f2c
Create Date: 2019-03-08 22:49:22.938000

"""

# revision identifiers, used by Alembic.
revision = 'd950ba31b98d'
down_revision = 'cb4742f68f2c'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table('user_notes',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('created', sa.DateTime, nullable=False),
        sa.Column('user_id', sa.Integer,
            sa.ForeignKey('user.id'), nullable=False),
        sa.Column('note', sa.Unicode)
    )


def downgrade():
    op.drop_table('user_notes')
