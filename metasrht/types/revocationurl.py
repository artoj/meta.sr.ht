import sqlalchemy as sa
import sqlalchemy_utils as sau
from srht.database import Base

class RevocationUrl(Base):
    __tablename__ = "revocationurl"
    id = sa.Column(sa.Integer, primary_key=True)
    created = sa.Column(sa.DateTime, nullable=False)
    updated = sa.Column(sa.DateTime, nullable=False)
    url = sa.Column(sa.String(2048), nullable=False)

    token_id = sa.Column(sa.Integer,
            sa.ForeignKey("oauthtoken.id", ondelete="CASCADE"),
            nullable=False)
    token = sa.orm.relationship(
            "OAuthToken",
            backref=sa.orm.backref("revocation_urls", cascade='all, delete'))

    client_id = sa.Column(sa.Integer,
            sa.ForeignKey("oauthclient.id", ondelete="CASCADE"),
            nullable=False)
    client = sa.orm.relationship("OAuthClient")

    def __init__(self, client, token, url):
        self.client_id = client.id
        self.token_id = token.id
        self.url = url
