"""Fix missing cascades

Revision ID: 8bf166ebda01
Revises: dd0274654d4e
Create Date: 2022-11-03 13:23:36.572482

"""

# revision identifiers, used by Alembic.
revision = '8bf166ebda01'
down_revision = 'dd0274654d4e'

from alembic import op
import sqlalchemy as sa

cascades = [
    ("user", "pgpkey", "pgp_key_id", "SET NULL"),
    ("user_webhook_subscription", "oauthtoken", "token_id", "CASCADE"),
    ("user_webhook_delivery", "user_webhook_subscription", "subscription_id", "CASCADE"),
]

def upgrade():
    for (table, relation, col, do) in cascades:
        op.execute(f"""
        ALTER TABLE "{table}" DROP CONSTRAINT IF EXISTS {table}_{col}_fkey;
        ALTER TABLE "{table}" ADD CONSTRAINT {table}_{col}_fkey
            FOREIGN KEY ({col})
            REFERENCES "{relation}"(id) ON DELETE {do};
        """)


def downgrade():
    for (table, relation, col, do) in tables:
        op.execute(f"""
        ALTER TABLE "{table}" DROP CONSTRAINT IF EXISTS {table}_{col}_fkey;
        ALTER TABLE "{table}" ADD CONSTRAINT {table}_{col}_fkey FOREIGN KEY ({col}) REFERENCES "{relation}"(id);
        """)
