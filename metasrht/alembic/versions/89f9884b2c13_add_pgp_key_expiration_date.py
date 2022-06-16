"""add pgp key expiration date

Revision ID: 89f9884b2c13
Revises: 8928d88c66d7
Create Date: 2022-05-16 14:40:46.261450

"""

# revision identifiers, used by Alembic.
revision = '89f9884b2c13'
down_revision = '8928d88c66d7'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.execute("""
    ALTER TABLE pgpkey
        ADD COLUMN expiration timestamp;
    """)


def downgrade():
    op.execute("""
    ALTER TABLE pgpkey
        DROP COLUMN expiration;
    """)
