import sqlalchemy as sa
from srht.database import Base
from srht.webhook import Webhook

class UserWebhook(Webhook):
    events = [
        "profile:update",
        "ssh-key:add",
        "ssh-key:remove",
        "pgp-key:add",
        "pgp-key:remove",
    ]
