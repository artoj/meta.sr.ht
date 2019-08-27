import sqlalchemy as sa
import sqlalchemy_utils as sau
import sshpubkeys as ssh
from srht.database import Base, db
from srht.oauth import current_token

class SSHKey(Base):
    __tablename__ = 'sshkey'
    id = sa.Column(sa.Integer, primary_key=True)
    created = sa.Column(sa.DateTime)
    user_id = sa.Column(sa.Integer, sa.ForeignKey('user.id'))
    user = sa.orm.relationship('User', backref=sa.orm.backref('ssh_keys'))
    key = sa.Column(sa.String(4096))
    fingerprint = sa.Column(sa.String(512))
    comment = sa.Column(sa.String(256))
    last_used = sa.Column(sa.DateTime)

    def __init__(self, user, valid):
        from metasrht.webhooks import UserWebhook
        from metasrht.audit import audit_log
        self.user = user
        self.user_id = user.id
        ssh_key = valid.require("ssh-key")
        if not valid.ok:
            return
        try:
            parsed_key = ssh.SSHKey(ssh_key)
            valid.expect(parsed_key.bits,
                    "This is not a valid SSH key", "ssh-key")
        except:
            valid.error("This is not a valid SSH key", "ssh-key")
        if not valid.ok:
            return
        fingerprint = parsed_key.hash_md5()[4:]
        valid.expect(SSHKey.query
            .filter(SSHKey.fingerprint == fingerprint)
            .count() == 0, "We already have this SSH key on file.", "ssh-key")
        if not valid.ok:
            return
        self.key = ssh_key
        self.fingerprint = fingerprint
        self.comment = parsed_key.comment
        db.session.flush()
        UserWebhook.deliver(
                UserWebhook.Events.ssh_key_add, self.to_dict(),
                UserWebhook.Subscription.user_id == self.user_id)
        audit_log("ssh key added", f"Added SSH key {fingerprint}")

    def delete(self):
        from metasrht.webhooks import UserWebhook
        from metasrht.audit import audit_log
        db.session.delete(self)
        UserWebhook.deliver(
                UserWebhook.Events.ssh_key_remove, { "id": self.id },
                UserWebhook.Subscription.user_id == self.user_id)
        audit_log("ssh key deleted", f"Deleted SSH key {self.fingerprint}")

    def __repr__(self):
        return '<SSHKey {} {}>'.format(self.id, self.fingerprint)

    def to_dict(self):
        return {
            "id": self.id,
            "authorized": self.created,
            "comment": self.comment,
            "fingerprint": self.fingerprint,
            "key": self.key,
            "owner": self.user.to_dict(short=True),
            **({
                "last_used": self.last_used,
            } if current_token and current_token.user_id == self.user_id else {})
        }
