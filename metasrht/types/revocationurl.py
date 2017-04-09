import sqlalchemy as sa
import sqlalchemy_utils as sau
from srht.database import Base

class RevocationUrl(Base):
    __tablename__ = 'revocationurl'
    id = sa.Column(sa.Integer, primary_key=True)
    created = sa.Column(sa.DateTime, nullable=False)
    updated = sa.Column(sa.DateTime, nullable=False)
    token_id = sa.Column(sa.Integer, sa.ForeignKey('oauthtoken.id'), nullable=False)
    token = sa.orm.relationship('OAuthToken', backref=sa.orm.backref('revocation_urls'))
    url = sa.Column(sa.String(2048), nullable=False)

    def __init__(self, token, url):
        self.token_id = token.id
        self.url = url
