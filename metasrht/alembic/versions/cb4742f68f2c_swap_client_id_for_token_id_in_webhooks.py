"""Swap client_id for token_id in webhooks

Revision ID: cb4742f68f2c
Revises: 82ff5fc58b75
Create Date: 2019-02-12 20:38:36.940962

"""

# revision identifiers, used by Alembic.
revision = 'cb4742f68f2c'
down_revision = '82ff5fc58b75'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.drop_column('user_webhook_subscription', 'client_id')
    op.add_column('user_webhook_subscription',
            sa.Column('token_id', sa.Integer, sa.ForeignKey("oauthtoken.id")))


def downgrade():
    op.drop_column('user_webhook_subscription', 'token_id')
    op.add_column('user_webhook_subscription',
            sa.Column('client_id', sa.Integer, sa.ForeignKey("oauthclient.id")))
