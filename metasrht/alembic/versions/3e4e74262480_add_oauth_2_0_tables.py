"""Add OAuth 2.0 tables

Revision ID: 3e4e74262480
Revises: 0972ddb8d4f8
Create Date: 2020-09-08 18:00:31.420562

"""

# revision identifiers, used by Alembic.
revision = '3e4e74262480'
down_revision = '2d417400aa37'

from alembic import op
import sqlalchemy as sa
import sqlalchemy_utils as sau


def upgrade():
    op.create_table("oauth2_client",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("created", sa.DateTime, nullable=False),
        sa.Column("updated", sa.DateTime, nullable=False),
        sa.Column("owner_id", sa.Integer,
                sa.ForeignKey("user.id", ondelete="CASCADE"),
                nullable=False),
        sa.Column("client_uuid", sau.UUIDType, nullable=False),
        sa.Column("client_secret_hash", sa.String(128), nullable=False),
        sa.Column("client_secret_partial", sa.String(8), nullable=False),
        sa.Column("redirect_url", sa.Unicode),
        sa.Column("client_name", sa.Unicode(256), nullable=False),
        sa.Column("client_description", sa.Unicode),
        sa.Column("client_url", sa.Unicode))
    op.create_table("oauth2_grant",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("issued", sa.DateTime, nullable=False),
        sa.Column("expires", sa.DateTime, nullable=False),
        sa.Column("comment", sa.Unicode),
        sa.Column("token_hash", sa.String(128), nullable=False),
        sa.Column("user_id", sa.Integer,
                sa.ForeignKey("user.id", ondelete="CASCADE"),
                nullable=False),
        sa.Column("client_id", sa.Integer,
                sa.ForeignKey("oauth2_client.id", ondelete="CASCADE")))

def downgrade():
    op.drop_table("oauth2_grant")
    op.drop_table("oauth2_client")
