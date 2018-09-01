from srht.flask import SrhtFlask
from srht.config import cfg, load_config
load_config("meta")

from srht.database import DbSession
db = DbSession(cfg("sr.ht", "connection-string"))

from metasrht.types import User, UserType
db.init()

from metasrht.blueprints.api import api
from metasrht.blueprints.auth import auth
from metasrht.blueprints.invites import invites
from metasrht.blueprints.keys import keys
from metasrht.blueprints.oauth import oauth
from metasrht.blueprints.privacy import privacy
from metasrht.blueprints.profile import profile
from metasrht.blueprints.security import security

class MetaApp(SrhtFlask):
    def __init__(self):
        super().__init__("meta", __name__)

        self.register_blueprint(api)
        self.register_blueprint(auth)
        self.register_blueprint(invites)
        self.register_blueprint(keys)
        self.register_blueprint(oauth)
        self.register_blueprint(privacy)
        self.register_blueprint(profile)
        self.register_blueprint(security)

        @self.context_processor
        def inject():
            return {
                'owner': cfg("meta.sr.ht", "owner-name"),
                'owner_email': cfg("meta.sr.ht", "owner-email"),
                'UserType': UserType,
            }

        @self.login_manager.user_loader
        def load_user(username):
            # TODO: Session tokens
            return User.query.filter(User.username == username).first()

app = MetaApp()
