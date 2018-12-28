"""Add webhook tables

Revision ID: 18a2c6a540bc
Revises: f1f6b32242fe
Create Date: 2018-12-27 23:54:43.334311

"""

# revision identifiers, used by Alembic.
revision = '18a2c6a540bc'
down_revision = 'f1f6b32242fe'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table('webhook',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('created', sa.DateTime, nullable=False),
        sa.Column('updated', sa.DateTime, nullable=False),
        sa.Column('user_id', sa.Integer, sa.ForeignKey("user.id")),
        sa.Column('client_id', sa.Integer,
            sa.ForeignKey("oauthclient.id", ondelete="CASCADE")),
        sa.Column('url', sa.Unicode(2048), nullable=False),
        sa.Column('events', sa.Unicode, nullable=False))
    op.create_table('webhook_delivery',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('created', sa.DateTime, nullable=False),
        sa.Column('event', sa.Unicode(256), nullable=False),
        sa.Column('webhook_id', sa.Integer,
            sa.ForeignKey("webhook.id", ondelete="CASCADE"),
            nullable=False),
        sa.Column('url', sa.Unicode(2048), nullable=False),
        sa.Column('payload', sa.Unicode(16384), nullable=False),
        sa.Column('payload_headers', sa.Unicode(16384), nullable=False),
        sa.Column('response', sa.Unicode(16384), nullable=False),
        sa.Column('response_status', sa.Integer, nullable=False),
        sa.Column('response_headers', sa.Unicode(16384), nullable=False))


def downgrade():
    op.drop_table('webhook_delivery')
    op.drop_table('webhook')
