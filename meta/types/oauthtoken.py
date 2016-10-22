import sqlalchemy as sa
import sqlalchemy_utils as sau
from datetime import datetime, timedelta
from meta.db import Base
import hashlib
import binascii
import os

class OAuthToken(Base):
    __tablename__ = 'oauthtoken'
    id = sa.Column(sa.Integer, primary_key=True)
    created = sa.Column(sa.DateTime, nullable=False)
    updated = sa.Column(sa.DateTime, nullable=False)
    expires = sa.Column(sa.DateTime, nullable=False)
    user_id = sa.Column(sa.Integer, sa.ForeignKey('user.id'))
    user = sa.orm.relationship('User', backref=sa.orm.backref('oauth_tokens'))
    client_id = sa.Column(sa.Integer, sa.ForeignKey('oauthclient.id'))
    client = sa.orm.relationship('OAuthClient', backref=sa.orm.backref('tokens'))
    token_hash = sa.Column(sa.String(32), nullable=False)
    token_partial = sa.Column(sa.String(8), nullable=False)
    scopes = sa.Column(sa.String(512), nullable=False)

    def __init__(self, user, client):
        self.user_id = user.id
        self.client_id = client.id if client else None
        self.expires = datetime.now() + timedelta(years=1)

    def gen_token(self):
        token = binascii.hexlify(os.urandom(16)).decode()
        self.token_partial = token[:8]
        self.token_hash = hashlib.sha512(token.encode()).hexdigest()
        return token
