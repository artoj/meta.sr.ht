"""Increase size of pgp key column

Revision ID: e5f8d19beac2
Revises: 7505107f9372
Create Date: 2017-04-06 21:38:44.908745

"""

# revision identifiers, used by Alembic.
revision = 'e5f8d19beac2'
down_revision = '7505107f9372'

from alembic import op
import sqlalchemy as sa


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column("pgpkey", "key", type_=sa.String(16384))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column("pgpkey", "key", type_=sa.String(4096))
    # ### end Alembic commands ###