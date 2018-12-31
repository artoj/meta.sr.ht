"""Add user webhook tables

Revision ID: 82ff5fc58b75
Revises: 18a2c6a540bc
Create Date: 2018-12-31 12:27:28.960511

"""

# revision identifiers, used by Alembic.
revision = '82ff5fc58b75'
down_revision = '18a2c6a540bc'

from alembic import op
import sqlalchemy as sa
import sqlalchemy_utils as sau


def upgrade():
    op.drop_table('webhook_delivery')
    op.drop_table('webhook')
    op.create_table('user_webhook_subscription',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('created', sa.DateTime, nullable=False),
        sa.Column('url', sa.Unicode(2048), nullable=False),
        sa.Column('events', sa.Unicode, nullable=False),
        sa.Column('user_id', sa.Integer,
            sa.ForeignKey("user.id")),
        sa.Column('client_id', sa.Integer,
            sa.ForeignKey("oauthclient.id")))
    op.create_table('user_webhook_delivery',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('uuid', sau.UUIDType, nullable=False),
        sa.Column('created', sa.DateTime, nullable=False),
        sa.Column('event', sa.Unicode(256), nullable=False),
        sa.Column('url', sa.Unicode(2048), nullable=False),
        sa.Column('payload', sa.Unicode(16384), nullable=False),
        sa.Column('payload_headers', sa.Unicode(16384), nullable=False),
        sa.Column('response', sa.Unicode(16384)),
        sa.Column('response_status', sa.Integer, nullable=False),
        sa.Column('response_headers', sa.Unicode(16384)),
        sa.Column('subscription_id', sa.Integer,
            sa.ForeignKey("user_webhook_subscription.id")))


def downgrade():
    op.drop_table('user_webhook_subscription')
    op.drop_table('user_webhook_delivery')
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
