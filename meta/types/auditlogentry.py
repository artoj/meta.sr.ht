import sqlalchemy as sa
import sqlalchemy_utils as sau
from enum import Enum
from meta.db import Base

class EventType(Enum):
    created_account = "created account"
    logged_in = "logged in"
    logged_out = "logged out"
    updated_profile = "updated profile"
    updated_email = "updated email"
    enabled_two_factor = "enabled two factor"
    disabled_two_factor = "disabled two factor"
    reset_password = "reset password"
    add_ssh_key = "added ssh key"
    deleted_ssh_key = "deleted ssh key"
    add_pgp_key = "added pgp key"
    deleted_pgp_key = "deleted pgp key"
    authorized_oauth_client = "authorized oauth client"
    revoked_oauth_token = "revoked oauth token"
    registered_oauth_client = "registered oauth client"
    reset_client_secret = "reset client secret"
    revoked_client_keys = "revoked client keys"
    deleted_oauth_client = "deleted oauth client"
    issued_personal_oauth_token = "issued personal oauth token"
    linked_external_account = "linked external account"
    updated_credit_card = "updated credit card"
    updated_billing_address = "updated billing address"

class AuditLogEntry(Base):
    __tablename__ = 'audit_log_entry'
    id = sa.Column(sa.Integer, primary_key=True)
    created = sa.Column(sa.DateTime, nullable=False)
    user_id = sa.Column(sa.Integer,
            sa.ForeignKey('user.id'),
            nullable=False)
    user = sa.orm.relationship('User', backref=sa.orm.backref('audit_log'))
    event_type = sa.Column(
            sau.ChoiceType(EventType, impl=sa.String()),
            nullable=False)
    ip_address = sa.Column(sau.IPAddressType, nullable=False)
    details = sa.Column(sa.Unicode(512))

    def __init__(self, user_id, event_type, ip_address, details):
        self.user_id = user_id
        self.event_type = event_type
        self.ip_address = ip_address
        self.details = details

    def __repr__(self):
        return "<AuditLogEntry {} {} {}>".format(
                self.id, self.ip_address, self.type)
