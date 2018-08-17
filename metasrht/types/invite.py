import sqlalchemy as sa
import sqlalchemy_utils as sau
from srht.database import Base
import base64
import os

class Invite(Base):
    __tablename__ = 'invite'
    id = sa.Column(sa.Integer, primary_key=True)
    created = sa.Column(sa.DateTime, nullable=False)
    updated = sa.Column(sa.DateTime, nullable=False)
    invite_hash = sa.Column(sa.String(128))
    sender_id = sa.Column(sa.Integer, sa.ForeignKey('user.id'))
    sender = sa.orm.relationship('User',
            backref=sa.orm.backref('invites_sent'),
            foreign_keys=[sender_id])
    recipient_id = sa.Column(sa.Integer, sa.ForeignKey('user.id'))
    recipient = sa.orm.relationship('User', foreign_keys=[recipient_id])

    def gen_invite_hash(self):
        self.invite_hash = base64.urlsafe_b64encode(os.urandom(18)) \
            .decode('utf-8')

    def __init__(self):
        self.gen_invite_hash()

    def __repr__(self):
        return '<Invite {}>'.format(self.id)
