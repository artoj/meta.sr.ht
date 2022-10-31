"""Add cascades for user deletion

Revision ID: dd0274654d4e
Revises: 1e8d4da5c25f
Create Date: 2022-10-31 13:31:44.004480

"""

# revision identifiers, used by Alembic.
revision = 'dd0274654d4e'
down_revision = '1e8d4da5c25f'

from alembic import op
import sqlalchemy as sa


tables = [
    ("audit_log_entry", "user_id"),
    ("gql_profile_wh_sub", "user_id"),
    ("invoice", "user_id"),
    ("oauthclient", "user_id"),
    ("oauthtoken", "user_id"),
    ("pgpkey", "user_id"),
    ("sshkey", "user_id"),
    ("user_auth_factor", "user_id"),
    ("user_notes", "user_id"),
    ("user_webhook_subscription", "user_id"),
    ("webhook_subscription", "user_id"),
]

def upgrade():
    for (table, col) in tables:
        op.execute(f"""
        ALTER TABLE {table} DROP CONSTRAINT {table}_{col}_fkey;
        ALTER TABLE {table} ADD CONSTRAINT {table}_{col}_fkey FOREIGN KEY ({col}) REFERENCES "user"(id) ON DELETE CASCADE;
        """)


def downgrade():
    for (table, col) in tables:
        op.execute(f"""
        ALTER TABLE {table} DROP CONSTRAINT {table}_{col}_fkey;
        ALTER TABLE {table} ADD CONSTRAINT {table}_{col}_fkey FOREIGN KEY ({col}) REFERENCES "user"(id);
        """)
