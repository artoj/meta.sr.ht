from collections import namedtuple
from metasrht.types.webhook import Webhook, WebhookDelivery, EventSubscription

_webhook = namedtuple('_webhook',
        ['resource', 'oauth_scope', 'events', 'resource_func'])
_webhooks = dict()

def register_webhook(resource, oauth_scope, events, resource_func=None):
    _webhooks[resource] = _webhook(resource, oauth_scope, events, resource_func)

def get_webhook(resource):
    return _webhooks[resource]

def get_webhooks():
    return _webhooks.values()

def validate_subscription(token, sub):
    return True # TODO: validate resource+event+ids exist, validate scopes

def deliver_webhook(resource, event, affected_ids, payload,
        client_id=None, user_id=None, **payload_headers):
    assert client_id is not None or user_id is not None
    # TODO
