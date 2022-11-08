"""Add reserved accounts table

Revision ID: 20ca7d8cb982
Revises: 8bf166ebda01
Create Date: 2022-11-08 11:59:30.633263

"""

# revision identifiers, used by Alembic.
revision = '20ca7d8cb982'
down_revision = '8bf166ebda01'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.execute("""
    CREATE TABLE reserved_usernames (
        username varchar NOT NULL
    );

    CREATE INDEX reserved_usernames_ix ON reserved_usernames(username);
    """)


def downgrade():
    op.execute("""
    DROP INDEX reserved_usernames_ix;
    DROP TABLE reserved_usernames;
    """)
