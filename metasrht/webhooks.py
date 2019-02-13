from srht.webhook import Webhook, Event

class UserWebhook(Webhook):
    events = [
        Event("profile:update", "profile:read"),
        Event("ssh-key:add", "keys:read"),
        Event("ssh-key:remove", "keys:read"),
        Event("pgp-key:add", "keys:read"),
        Event("pgp-key:remove", "keys:read"),
    ]
