import pgpy
import pgpy.constants
import sqlalchemy as sa
import sqlalchemy_utils as sau
from enum import Enum
from jinja2 import Markup
from srht.database import Base
from srht.email import prepare_email

class PGPKey(Base):
    __tablename__ = 'pgpkey'
    id = sa.Column(sa.Integer, primary_key=True)
    created = sa.Column(sa.DateTime)
    user_id = sa.Column(sa.Integer, sa.ForeignKey('user.id'))
    user = sa.orm.relationship('User',
            backref=sa.orm.backref('pgp_keys'),
            foreign_keys=[user_id])
    key = sa.Column(sa.String(32768))
    key_id = sa.Column(sa.String(512))
    email = sa.Column(sa.String(256))

    def __init__(self, user, valid):
        from metasrht.webhooks import UserWebhook
        from metasrht.audit import audit_log
        self.user = user
        self.user_id = user.id
        pgp_key = valid.require("pgp-key")
        valid.expect(not pgp_key or len(pgp_key) < 32768,
                Markup("Maximum encoded key length is 32768 bytes. "
                    "Try <br /><code>gpg --armor --export-options export-minimal "
                    "--export &lt;fingerprint&gt;</code><br /> to export a "
                    "smaller key."),
                field="pgp-key")
        if valid.ok:
            try:
                key = pgpy.PGPKey()
                key.parse(pgp_key.replace('\r', '').encode('utf-8'))
                valid.expect(any(key.userids),
                        "This key has no user IDs", field="pgp-key")
            except Exception as ex:
                valid.error("This is not a valid PGP key", field="pgp-key")
        if valid.ok:
            try:
                prepare_email("test", user.email, "test", encrypt_key=pgp_key)
            except Exception as ex:
                valid.error(
                        "We were unable to encrypt a test message with this key",
                        field="pgp-key")
        if valid.ok:
            valid.expect(PGPKey.query
                .filter(PGPKey.user_id == user.id)
                .filter(PGPKey.key_id == key.fingerprint)
                .count() == 0, "This is a duplicate key", field="pgp-key")
        if not valid.ok:
            return
        self.key = pgp_key
        self.key_id = key.fingerprint
        self.email = key.userids[0].email
        audit_log("pgp key added", f"Added PGP key {key.fingerprint}")
        UserWebhook.deliver(UserWebhook.Events.pgp_key_add,
                self.to_dict(), UserWebhook.Subscription.user_id == user.id)

    def __repr__(self):
        return '<PGPKey {} {}>'.format(self.id, self.key_id)

    def to_dict(self):
        return {
            "id": self.id,
            "key": self.key,
            "key_id": self.key_id,
            "email": self.email,
            "authorized": self.created,
            "owner": self.user.to_dict(short=True),
        }
