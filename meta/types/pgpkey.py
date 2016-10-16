import sqlalchemy as sa
import sqlalchemy_utils as sau
from meta.db import Base
from enum import Enum

class PGPKey(Base):
    __tablename__ = 'pgpkey'
    id = sa.Column(sa.Integer, primary_key=True)
    user_id = sa.Column(sa.Integer, sa.ForeignKey('user.id'))
    user = sa.orm.relationship('User', backref=sa.orm.backref('pgp_keys'))
    key = sa.Column(sa.String(4096))
    key_id = sa.Column(sa.String(512))
    email = sa.Column(sa.String(256))

    def __init__(self, key, key_id):
        self.key = key
        self.key_id = key_id

    def __repr__(self):
        return '<PGPKey {} {}>'.format(self.id, self.key_id)
