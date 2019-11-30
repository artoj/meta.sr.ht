import sqlalchemy as sa
from datetime import datetime, timedelta
from srht.database import Base
from srht.oauth import OAuthTokenMixin
import hashlib
import binascii
import os

class OAuthToken(Base, OAuthTokenMixin):
    @property
    def first_party(self):
        return not self.client or self.client.preauthorized

    def __init__(self, user=None, client=None):
        self.user_id = user.id if user else None
        self.client_id = client.id if client else None
        self.expires = datetime.utcnow() + timedelta(days=365)

    def gen_token(self):
        token = binascii.hexlify(os.urandom(16)).decode()
        self.token_partial = token[:8]
        self.token_hash = hashlib.sha512(token.encode()).hexdigest()
        return token
