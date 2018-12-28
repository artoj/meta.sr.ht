import re
import sqlalchemy as sa
import sqlalchemy_utils as sau
from srht.database import Base

event_re = re.compile(r"""
        (?P<resource>[a-z]+):(?P<events>[a-z+]+)
        (\[(?P<ids>[0-9,]+)\])?""", re.X)

class EventSubscription:
    def __init__(self, definition):
        match = event_re.fullmatch(definition)
        if not match:
            raise Exception("Invalid event definition " + definition)
        self.resource = match.group("resource")
        self.events = match.group("events")
        self.events = self.events.split('+')
        self.ids = match.group("ids")
        if self.ids:
            self.ids = self.ids.split(',')
            # TODO: Maybe catch non-ints and give a nice ol' error
            self.ids = [int(i) for i in self.ids]

    def __str__(self):
        s = f"{self.resource}:{'+'.join(self.events)}"
        if self.ids and any(self.ids):
            s += f"[{','.join(str(i) for i in self.ids)}]"
        return s

class Webhook(Base):
    __tablename__ = 'webhook'
    id = sa.Column(sa.Integer, primary_key=True)
    created = sa.Column(sa.DateTime, nullable=False)
    updated = sa.Column(sa.DateTime, nullable=False)
    user_id = sa.Column(sa.Integer, sa.ForeignKey("user.id"))
    user = sa.orm.relationship('User', backref=sa.orm.backref('webhooks'))
    client_id = sa.Column(sa.Integer,
            sa.ForeignKey("oauthclient.id", ondelete="CASCADE"))
    client = sa.orm.relationship('OAuthClient', cascade='all, delete')
    url = sa.Column(sa.Unicode(2048), nullable=False)
    _events = sa.Column(sa.Unicode, nullable=False, name="events")

    @property
    def events(self):
        return [EventSubscription(e) for e in self._events.split(";")]

    @events.setter
    def events(self, val):
        self._events = ";".join(str(v) for v in val)

    def __repr__(self):
        return '<Webhook {}>'.format(self.id)

    def to_dict(self):
        return {
            "id": self.id,
            "created": self.created,
            "updated": self.updated,
            "url": self.url,
            "events": [str(ev) for ev in self.events],
        }

class WebhookDelivery(Base):
    __tablename__ = 'webhook_delivery'
    id = sa.Column(sa.Integer, primary_key=True)
    created = sa.Column(sa.DateTime, nullable=False)
    event = sa.Column(sa.Unicode(256), nullable=False)
    webhook_id = sa.Column(sa.Integer,
            sa.ForeignKey("webhook.id", ondelete="CASCADE"),
            nullable=False)
    webhook = sa.orm.relationship("Webhook",
            backref=sa.orm.backref('deliveries', cascade='all, delete'))
    url = sa.Column(sa.Unicode(2048), nullable=False)
    payload = sa.Column(sa.Unicode(16384), nullable=False)
    payload_headers = sa.Column(sa.Unicode(16384), nullable=False)
    response = sa.Column(sa.Unicode(16384), nullable=False)
    response_status = sa.Column(sa.Integer, nullable=False)
    response_headers = sa.Column(sa.Unicode(16384), nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "created": self.created,
            "event": self.event,
            "webhook_id": self.webhook_id,
            "url": self.url,
            "payload": self.payload,
            "payload_headers": self.payload_headers,
            "response": self.response,
            "response_status": self.response_status,
            "response_headers": self.response_headers,
        }
