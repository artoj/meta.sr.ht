from srht.config import cfg
from srht.database import DbSession, db
if not hasattr(db, "session"):
    # Initialize the database if not already configured (for running daemon)
    db = DbSession(cfg("meta.sr.ht", "connection-string"))
    import metasrht.types
    db.init()
from srht.webhook import Event
from srht.webhook.celery import CeleryWebhook, make_worker

worker = make_worker()

class UserWebhook(CeleryWebhook):
    events = [
        Event("profile:update", "profile:read"),
        Event("ssh-key:add", "keys:read"),
        Event("ssh-key:remove", "keys:read"),
        Event("pgp-key:add", "keys:read"),
        Event("pgp-key:remove", "keys:read"),
    ]
