import metasrht.webhooks
from metasrht.oauth import MetaOAuthService, MetaOAuthProvider
from metasrht.types import User, UserType
from prometheus_client import make_wsgi_app
from srht.config import cfg
from srht.database import DbSession
from srht.flask import SrhtFlask
from urllib.parse import quote_plus
from werkzeug.wsgi import DispatcherMiddleware

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
        from metasrht.blueprints.privacy import privacy
        from metasrht.blueprints.profile import profile
        from metasrht.blueprints.security import security

        self.register_blueprint(auth)
        self.register_blueprint(invites)
        self.register_blueprint(keys)
        self.register_blueprint(oauth_exchange)
        self.register_blueprint(oauth_web)
        self.register_blueprint(privacy)
        self.register_blueprint(profile)
        self.register_blueprint(security)
        register_api(self)

        if cfg("meta.sr.ht::billing", "enabled") == "yes":
            from metasrht.blueprints.billing import billing
            self.register_blueprint(billing)

        @self.context_processor
        def inject():
            return { 'UserType': UserType }

        @self.login_manager.user_loader
        def load_user(username):
            # TODO: Session tokens
            return User.query.filter(User.username == username).first()

app = MetaApp()

app_dispatch = DispatcherMiddleware(app, {
    '/metrics': make_wsgi_app()
})
