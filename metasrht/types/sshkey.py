import sqlalchemy as sa
import sqlalchemy_utils as sau
from srht.database import Base
from srht.oauth import current_token
from enum import Enum

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

    def __init__(self, user, key, fingerprint, comment=None):
        self.user_id = user.id
        self.key = key
        self.fingerprint = fingerprint
        self.comment = comment

    def __repr__(self):
        return '<SSHKey {} {}>'.format(self.id, self.fingerprint)

    def to_dict(self):
        return {
            "id": self.id,
            "authorized": self.created,
            "comment": self.comment,
            "fingerprint": self.fingerprint,
            "key": self.key,
            "owner": self.user.to_dict(),
            **({
                "last_used": self.last_used,
            } if current_token and current_token.user_id == self.user_id else {})
        }
