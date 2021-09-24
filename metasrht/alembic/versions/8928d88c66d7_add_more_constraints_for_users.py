"""Add more constraints for users

Revision ID: 8928d88c66d7
Revises: a08050104214
Create Date: 2021-09-24 09:13:17.167274

"""

# revision identifiers, used by Alembic.
revision = '8928d88c66d7'
down_revision = 'a08050104214'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.execute("""
    ALTER TABLE "user"
    ADD CONSTRAINT user_email_unique UNIQUE (email);
    """)


def downgrade():
    op.execute("""
    ALTER TABLE "user"
    DROP CONSTRAINT user_email_unique;
    """)
