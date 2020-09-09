from flask import session
from metasrht.auth import allow_registration, is_external_auth, allow_password_reset
from metasrht.oauth import MetaOAuthService, MetaOAuthProvider
from metasrht.types import UserType
from srht.config import cfg
from srht.database import DbSession
from srht.flask import SrhtFlask

db = DbSession(cfg("meta.sr.ht", "connection-string"))
db.init()

class MetaApp(SrhtFlask):
    def __init__(self):
        super().__init__("meta.sr.ht", __name__,
                oauth_service=MetaOAuthService(),
                oauth_provider=MetaOAuthProvider())

        from metasrht.blueprints.api import register_api
        from metasrht.blueprints.auth import auth
        from metasrht.blueprints.invites import invites
        from metasrht.blueprints.keys import keys
        from metasrht.blueprints.oauth_exchange import oauth_exchange
        from metasrht.blueprints.oauth_web import oauth_web
        from metasrht.blueprints.oauth2 import oauth2
        from metasrht.blueprints.privacy import privacy
        from metasrht.blueprints.profile import profile
        from metasrht.blueprints.security import security
        from metasrht.blueprints.users import users
        from srht.graphql import gql_blueprint

        self.register_blueprint(auth)
        self.register_blueprint(invites)
        self.register_blueprint(keys)
        self.register_blueprint(oauth_exchange)
        self.register_blueprint(oauth_web)
        self.register_blueprint(oauth2)
        self.register_blueprint(privacy)
        self.register_blueprint(profile)
        self.register_blueprint(security)
        self.register_blueprint(users)
        register_api(self)
        self.register_blueprint(gql_blueprint)

        self.jinja_env.globals['allow_registration'] = allow_registration
        self.jinja_env.globals['allow_password_reset'] = allow_password_reset
        self.jinja_env.globals['is_external_auth'] = is_external_auth

        if cfg("meta.sr.ht::billing", "enabled") == "yes":
            from metasrht.blueprints.billing import billing
            self.register_blueprint(billing)

        @self.context_processor
        def inject():
            return {
                'UserType': UserType,
                'notice': session.pop('notice', None),
            }

app = MetaApp()
