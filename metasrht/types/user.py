import sqlalchemy as sa
import sqlalchemy_utils as sau
from srht.database import Base
from srht.oauth import UserMixin, UserType
from enum import Enum
from datetime import datetime, timedelta
import base64
import os

class PaymentInterval(Enum):
    monthly = "monthly"
    yearly = "yearly"

class User(Base, UserMixin):
    password = sa.Column(sa.String(256), nullable=False)
    new_email = sa.Column(sa.String(256))
    confirmation_hash = sa.Column(sa.String(128))
    # TODO: Consider moving pgp key into UserMixin
    pgp_key_id = sa.Column(sa.Integer, sa.ForeignKey('pgpkey.id'))
    pgp_key = sa.orm.relationship('PGPKey', foreign_keys=[pgp_key_id])
    reset_hash = sa.Column(sa.String(128))
    reset_expiry = sa.Column(sa.DateTime())
    invites = sa.Column(sa.Integer, server_default='0')
    "Number of invites this user can send"
    stripe_customer = sa.Column(sa.String(256))
    payment_cents = sa.Column(
            sa.Integer, nullable=False, server_default='0')
    payment_interval = sa.Column(
            sau.ChoiceType(PaymentInterval, impl=sa.String()),
            server_default='monthly')
    payment_due = sa.Column(sa.DateTime)
    welcome_emails = sa.Column(sa.Integer, nullable=False, server_default='0')

    def __init__(self, username):
        self.username = username
        self.gen_confirmation_hash()

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

    def to_dict(self, first_party=False):
        return {
            "canonical_name": self.canonical_name,
            "name": self.username,
            "email": self.email,
            "url": self.url,
            "location": self.location,
            "bio": self.bio,
            "use_pgp_key": self.pgp_key.key_id if self.pgp_key else None,
            **({
                "user_type": self.user_type.value,
            } if first_party else {})
        }
