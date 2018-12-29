from flask import Blueprint, request, abort
from srht.api import paginated_response
from srht.database import db
from srht.oauth import oauth, current_token
from srht.validation import Validation
from metasrht.types import Webhook, WebhookDelivery, EventSubscription
from metasrht.webhooks import get_webhook, get_webhooks, validate_subscription

webhooks = Blueprint('api.webhooks', __name__)

@webhooks.route("/api/webhooks/events")
def webhooks_events_GET():
    return [
        {
            "resource": wh.resource,
            "events": wh.events,
            "required_scope": wh.oauth_scope,
        } for wh in get_webhooks()
    ]

@webhooks.route("/api/webhooks")
@oauth(None)
def webhooks_GET():
    return paginated_response(Webhook.id,
            Webhook.query.filter(Webhook.client_id == current_token.client_id))

@webhooks.route("/api/webhooks", methods=["POST"])
@oauth(None)
def webhooks_POST():
    valid = Validation(request)
    url = valid.require("url", cls=str)
    events = valid.require("events", cls=list)
    valid.expect(events is None or all(isinstance(e, str) for e in events),
            "Expected events to be a list of strings", field="events")
    if not valid.ok:
        return valid.response
    webhook = Webhook()
    webhook.url = url
    valid.expect(any(events), "No events provided", field="events")
    webhook.events = [EventSubscription(e) for e in events]
    valid.expect(all(validate_subscription(current_token, e)
        for e in webhook.events), "Invalid events/resources requested",
        field="events")
    if not valid.ok:
        return valid.response
    webhook.client_id = current_token.client_id
    db.session.add(webhook)
    db.session.commit()
    return webhook.to_dict()

@webhooks.route("/api/webhooks/<int:hook_id>")
@oauth(None)
def webhooks_id_GET(hook_id):
    webhook = Webhook.query.filter(Webhook.id == hook_id).one_or_none()
    if not webhook:
        abort(404)
    if webhook.client_id != current_token.client_id:
        abort(401)
    return webhook.to_dict()

@webhooks.route("/api/webhooks/<int:hook_id>", methods=["DELETE"])
@oauth(None)
def webhooks_id_DELETE(hook_id):
    webhook = Webhook.query.filter(Webhook.id == hook_id).one_or_none()
    if not webhook:
        abort(404)
    if webhook.client_id != current_token.client_id:
        abort(401)
    db.session.delete(webhook)
    db.session.commit()
    return {}
