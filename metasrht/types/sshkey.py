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
    b64_key = sa.Column(sa.String(4096))
    key_type = sa.Column(sa.String(256))
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
        self.b64_key = extract_b64_key(ssh_key)
        self.key_type = parsed_key.key_type
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

def extract_b64_key(data):
    """Extract the base64 ssh key portion from an ssh public key.

    This function is adapted from the python-sshpubkeys project[0]. It is
    copied here because the sshpubkeys module currently has no public API to
    get the base64 portion of a key. Some error checking in this function has
    been edited out because this function should only be used when the key
    has already been parsed by the SSHKey class from the sshpubkeys module
    (which means this function was already called with error checking).

    [0] https://github.com/ojarva/python-sshpubkeys/blob/9d6289c717a79dd8e49311af647877c95ebc41d3/sshpubkeys/keys.py#L204
    """
    # Terribly inefficient way to remove options, but hey, it works.
    if not data.startswith("ssh-") and not data.startswith("ecdsa-"):
        quote_open = False
        for i, character in enumerate(data):
            if character == '"':  # only double quotes are allowed, no need to care about single quotes
                quote_open = not quote_open
            if quote_open:
                continue
            if character == " ":
                # Data begins after the first space
                data = data[i + 1:]
                break
    key_parts = data.strip().split(None, 2)
    return key_parts[1]
