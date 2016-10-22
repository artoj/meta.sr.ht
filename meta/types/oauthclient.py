import sqlalchemy as sa
import sqlalchemy_utils as sau
from meta.db import Base
import hashlib
import binascii
import os

class OAuthClient(Base):
    __tablename__ = 'oauthclient'
    id = sa.Column(sa.Integer, primary_key=True)
    created = sa.Column(sa.DateTime, nullable=False)
    updated = sa.Column(sa.DateTime, nullable=False)
    user_id = sa.Column(sa.Integer, sa.ForeignKey('user.id'))
    user = sa.orm.relationship('User', backref=sa.orm.backref('oauth_clients'))
    client_id = sa.Column(sa.String(16), nullable=False)
    client_secret_hash = sa.Column(sa.String(32), nullable=False)
    client_secret_partial = sa.Column(sa.String(8), nullable=False)
    redirect_uri = sa.Column(sa.String(256))

    def __init__(self, user):
        self.user_id = user.id
        self.gen_client_id()

    def gen_client_id(self):
        self.client_id = binascii.hexlify(os.urandom(8))

    def gen_client_secret(self):
        secret = binascii.hexlify(os.urandom(16)).decode()
        self.client_secret_partial = secret[:8]
        self.client_secret_hash = hashlib.sha512(secret).hexdigest()
        return secret
