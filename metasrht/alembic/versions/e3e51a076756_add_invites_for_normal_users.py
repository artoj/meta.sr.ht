"""Add invites for normal users

Revision ID: e3e51a076756
Revises: 9caaf5055676
Create Date: 2018-08-16 20:05:37.336441

"""

# revision identifiers, used by Alembic.
revision = 'e3e51a076756'
down_revision = '9caaf5055676'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('invite', sa.Column('sender_id', sa.Integer()))
    op.create_foreign_key('invite_sender_id_fkey',
            'invite', 'user', ['sender_id'], ['id'])
    op.add_column('invite', sa.Column('recipient_id', sa.Integer()))
    op.create_foreign_key('invite_recipient_id_fkey',
            'invite', 'user', ['recipient_id'], ['id'])
    op.add_column('user', sa.Column('invites',
        sa.Integer(), server_default='0'))


def downgrade():
    op.drop_constraint('invite_sender_id_fkey', 'invite', type_='foreignkey')
    op.drop_column('invite', 'sender_id')
    op.drop_constraint('invite_recipient_id_fkey', 'invite', type_='foreignkey')
    op.drop_column('invite', 'recipient_id')
    op.drop_column('user', 'invites')
