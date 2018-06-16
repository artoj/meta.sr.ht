"""Add cascades for oauth foreign keys

Revision ID: 839e4a29751a
Revises: 5a5fda549d80
Create Date: 2018-06-16 11:22:28.518692

"""

# revision identifiers, used by Alembic.
revision = '839e4a29751a'
down_revision = '5a5fda549d80'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.drop_constraint(
            constraint_name="revocationurl_client_id_fkey",
            table_name="revocationurl",
            type_="foreignkey")
    op.create_foreign_key(
            constraint_name="revocationurl_client_id_fkey",
            source_table="revocationurl",
            referent_table="oauthclient",
            local_cols=["client_id"],
            remote_cols=["id"],
            ondelete="CASCADE")
    op.drop_constraint(
            constraint_name="revocationurl_token_id_fkey",
            table_name="revocationurl",
            type_="foreignkey")
    op.create_foreign_key(
            constraint_name="revocationurl_token_id_fkey",
            source_table="revocationurl",
            referent_table="oauthtoken",
            local_cols=["token_id"],
            remote_cols=["id"],
            ondelete="CASCADE")
    op.drop_constraint(
            constraint_name="oauthtoken_client_id_fkey",
            table_name="oauthtoken",
            type_="foreignkey")
    op.create_foreign_key(
            constraint_name="oauthtoken_client_id_fkey",
            source_table="oauthtoken",
            referent_table="oauthclient",
            local_cols=["client_id"],
            remote_cols=["id"],
            ondelete="CASCADE")
    op.drop_constraint(
            constraint_name="delegatedscope_client_id_fkey",
            table_name="delegatedscope",
            type_="foreignkey")
    op.create_foreign_key(
            constraint_name="delegatedscope_client_id_fkey",
            source_table="delegatedscope",
            referent_table="oauthclient",
            local_cols=["client_id"],
            remote_cols=["id"],
            ondelete="CASCADE")


def downgrade():
    op.drop_constraint(
            constraint_name="revocationurl_client_id_fkey",
            table_name="revocationurl",
            type_="foreignkey")
    op.create_foreign_key(
            constraint_name="revocationurl_client_id_fkey",
            source_table="revocationurl",
            referent_table="oauthclient",
            local_cols=["client_id"],
            remote_cols=["id"])
    op.drop_constraint(
            constraint_name="revocationurl_token_id_fkey",
            table_name="revocationurl",
            type_="foreignkey")
    op.create_foreign_key(
            constraint_name="revocationurl_token_id_fkey",
            source_table="revocationurl",
            referent_table="oauthtoken",
            local_cols=["token_id"],
            remote_cols=["id"])
    op.drop_constraint(
            constraint_name="oauthtoken_client_id_fkey",
            table_name="oauthtoken",
            type_="foreignkey")
    op.create_foreign_key(
            constraint_name="oauthtoken_client_id_fkey",
            source_table="oauthtoken",
            referent_table="oauthclient",
            local_cols=["client_id"],
            remote_cols=["id"])
    op.drop_constraint(
            constraint_name="delegatedscope_client_id_fkey",
            table_name="delegatedscope",
            type_="foreignkey")
    op.create_foreign_key(
            constraint_name="delegatedscope_client_id_fkey",
            source_table="delegatedscope",
            referent_table="oauthclient",
            local_cols=["client_id"],
            remote_cols=["id"])
