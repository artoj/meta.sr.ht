import sqlalchemy as sa
import sqlalchemy_utils as sau
from srht.database import Base

class DelegatedScope(Base):
    __tablename__ = 'delegatedscope'
    id = sa.Column(sa.Integer, primary_key=True)
    created = sa.Column(sa.DateTime, nullable=False)
    updated = sa.Column(sa.DateTime, nullable=False)
    name = sa.Column(sa.String(256), nullable=False)
    description = sa.Column(sa.String(512), nullable=False)
    write = sa.Column(sa.Boolean, nullable=False, default=False)

    client_id = sa.Column(sa.Integer,
            sa.ForeignKey('oauthclient.id', ondelete='CASCADE'),
            nullable=False)
    client = sa.orm.relationship('OAuthClient',
            backref=sa.orm.backref('scopes', cascade='all, delete'))

    def __init__(self, client, name, description):
        self.client_id = client.id
        self.name = name
        self.description = description

    def to_dict(self):
        return {
            "id": self.id,
            "created": self.created,
            "updated": self.updated,
            "name": self.name,
            "description": self.description,
            "writable": self.write
        }
