"""Rename SQL indexes to PostgreSQL-style

Revision ID: 1e8d4da5c25f
Revises: 89f9884b2c13
Create Date: 2022-10-27 08:06:42.383032

"""

# revision identifiers, used by Alembic.
revision = '1e8d4da5c25f'
down_revision = '89f9884b2c13'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.execute("""
    ALTER INDEX key_index RENAME TO sshkey_md5_idx;
    DROP INDEX ix_user_username;
    ALTER TABLE "user" RENAME CONSTRAINT user_username_unique TO user_username_key;
    ALTER TABLE "user" RENAME CONSTRAINT user_email_unique TO user_email_key;
    """)

def downgrade():
    op.execute("""
    ALTER INDEX sshkey_md5_idx RENAME TO key_index;
    CREATE INDEX ix_user_username ON "user" USING btree (username);
    ALTER TABLE "user" RENAME CONSTRAINT user_username_key TO user_username_unique;
    ALTER TABLE "user" RENAME CONSTRAINT user_email_key TO user_email_unique;
    """)
