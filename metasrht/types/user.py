import sqlalchemy as sa
import sqlalchemy_utils as sau
from srht.database import Base
from enum import Enum
from datetime import datetime, timedelta
import base64
import os

class UserType(Enum):
    unconfirmed = "unconfirmed"
    active_non_paying = "active_non_paying"
    active_free = "active_free"
    active_paying = "active_paying"
    active_delinquent = "active_delinquent"
    admin = "admin"

class User(Base):
    __tablename__ = 'user'
    id = sa.Column(sa.Integer, primary_key=True)
    created = sa.Column(sa.DateTime, nullable=False)
    updated = sa.Column(sa.DateTime, nullable=False)
    username = sa.Column(sa.Unicode(256))
    password = sa.Column(sa.String(256), nullable=False)
    email = sa.Column(sa.String(256), nullable=False)
    new_email = sa.Column(sa.String(256))
    user_type = sa.Column(
            sau.ChoiceType(UserType, impl=sa.String()),
            nullable=False,
            default=UserType.unconfirmed)
    confirmation_hash = sa.Column(sa.String(128))
    url = sa.Column(sa.String(256))
    location = sa.Column(sa.Unicode(256))
    bio = sa.Column(sa.Unicode(4096))
    pgp_key_id = sa.Column(sa.Integer, sa.ForeignKey('pgpkey.id'))
    pgp_key = sa.orm.relationship('PGPKey', foreign_keys=[pgp_key_id])
    reset_hash = sa.Column(sa.String(128))
    reset_expiry = sa.Column(sa.DateTime())
    invites = sa.Column(sa.Integer, server_default='0')
    "Number of invites this user can send"

    def gen_confirmation_hash(self):
        self.confirmation_hash = (
            base64.urlsafe_b64encode(os.urandom(18))
        ).decode('utf-8')
        return self.confirmation_hash

    def gen_reset_hash(self):
        self.reset_hash = (
            base64.urlsafe_b64encode(os.urandom(18))
        ).decode('utf-8')
        self.reset_expiry = datetime.utcnow() + timedelta(hours=48)
        return self.reset_hash

    def __init__(self, username):
        self.username = username
        self.gen_confirmation_hash()

    def __repr__(self):
        return '<User {} {}>'.format(self.id, self.username)

    def is_authenticated(self):
        return True
    def is_active(self):
        return True
    def is_anonymous(self):
        return False
    def get_id(self):
        return self.username
