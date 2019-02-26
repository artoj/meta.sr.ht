import sqlalchemy as sa
import sqlalchemy_utils as sau
from srht.database import Base, db
from srht.oauth import UserMixin, UserType
from srht.validation import valid_url
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

    def to_dict(self, first_party=False, short=False):
        return {
            "canonical_name": self.canonical_name,
            **({
                "user_type": self.user_type.value,
            } if first_party else {}),
            **({
                "name": self.username,
                "email": self.email,
                "url": self.url,
                "location": self.location,
                "bio": self.bio,
                "use_pgp_key": self.pgp_key.key_id if self.pgp_key else None,
            } if not short else {})
        }

    def update(self, valid, api=False):
        from metasrht.audit import audit_log
        from metasrht.webhooks import UserWebhook

        email = valid.optional("email", self.email)
        email = email.strip()
        url = valid.optional("url", self.url)
        location = valid.optional("location", self.location)
        bio = valid.optional("bio", self.bio)

        valid.expect(not url or 0 <= len(url) <= 256,
                "URL must fewer than 256 characters.", "url")
        valid.expect(not url or valid_url(url),
                "URL must be a valid http or https URL", "url")
        valid.expect(not location or 0 <= len(location) <= 256,
                "Location must fewer than 256 characters.", "location")
        valid.expect(not bio or 0 <= len(bio) <= 4096,
                "Bio must fewer than 4096 characters.", "bio")

        if not valid.ok:
            return

        self.url = url
        self.location = location
        self.bio = bio

        new_email = self.email != email
        if new_email:
            valid.expect(len(email) <= 256,
                "Email must be no more than 256 characters.", "email")
            prev = User.query.filter(User.email == email).first()
            valid.expect(not prev,
                    "This email address is already in use.", "email")
            if not valid.ok:
                return
            self.new_email = email
            self.gen_confirmation_hash()
            send_email('update_email_old', self.email,
                'Your {} email address is changing'.format(site_name),
                new_email=email)
            send_email('update_email_new', self.new_email,
                'Confirm your {} email address change'.format(site_name),
                new_email=email)

        audit_log("updated profile" + (" via API" if api else ""))
        UserWebhook.deliver(UserWebhook.Events.profile_update, self.to_dict(),
                UserWebhook.Subscription.user_id == self.id)
