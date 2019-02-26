import sqlalchemy as sa
import sqlalchemy_utils as sau
from srht.database import Base
from enum import Enum

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

    def __init__(self, user, key, key_id, email):
        self.user_id = user.id
        self.key = key
        self.key_id = key_id
        self.email = email

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
