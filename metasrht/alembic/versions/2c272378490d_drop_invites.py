"""Drop invites

Revision ID: 2c272378490d
Revises: 20ca7d8cb982
Create Date: 2023-02-13 10:09:52.930567

"""

# revision identifiers, used by Alembic.
revision = '2c272378490d'
down_revision = '20ca7d8cb982'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.execute("""
    ALTER TABLE "user" DROP COLUMN invites;
    DROP TABLE invite;
    """)


def downgrade():
    op.execute("""
    ALTER TABLE "user" ADD COLUMN invites integer DEFAULT 0;

    CREATE TABLE invite (
        id serial PRIMARY KEY,
        created timestamp without time zone NOT NULL,
        updated timestamp without time zone NOT NULL,
        invite_hash character varying(128),
        sender_id integer,
        recipient_id integer
    );
    """)
