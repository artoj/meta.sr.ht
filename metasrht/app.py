from urllib.parse import quote_plus
from srht.flask import SrhtFlask, LoginConfig
from srht.config import cfg
from srht.database import DbSession

db = DbSession(cfg("meta.sr.ht", "connection-string"))

from metasrht.types import User, UserType

db.init()

class MetaLoginConfig(LoginConfig):
    def __init__(self):
        super().__init__(None, None, None)

    def oauth_url(self, return_to, scopes=[]):
        return "/login?return_to={}".format(quote_plus(return_to))

class MetaApp(SrhtFlask):
    def __init__(self):
        super().__init__("meta.sr.ht", __name__, login_config=MetaLoginConfig())

        from metasrht.blueprints.api import api
        from metasrht.blueprints.auth import auth
        from metasrht.blueprints.billing import billing
        from metasrht.blueprints.invites import invites
        from metasrht.blueprints.keys import keys
        from metasrht.blueprints.oauth import oauth
        from metasrht.blueprints.privacy import privacy
        from metasrht.blueprints.profile import profile
        from metasrht.blueprints.security import security

        self.register_blueprint(api)
        self.register_blueprint(auth)
        self.register_blueprint(invites)
        self.register_blueprint(keys)
        self.register_blueprint(oauth)
        self.register_blueprint(privacy)
        self.register_blueprint(profile)
        self.register_blueprint(security)

        self.no_csrf_prefixes = ['/api', '/oauth/exchange', '/oauth/token']

        if cfg("meta.sr.ht::billing", "enabled") == "yes":
            self.register_blueprint(billing)

        @self.context_processor
        def inject():
            return { 'UserType': UserType }

        @self.login_manager.user_loader
        def load_user(username):
            # TODO: Session tokens
            return User.query.filter(User.username == username).first()

app = MetaApp()
