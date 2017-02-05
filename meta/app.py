from flask import render_template, request
from flask_login import LoginManager, current_user

import random
import sys
import os
import locale

from srht.config import cfg, cfgi
from srht.database import DbSession
db = DbSession(cfg("sr.ht", "connection-string"))
from meta.types import User
db.init()

from srht.flask import SrhtFlask
app = SrhtFlask("meta", __name__)
app.secret_key = cfg("server", "secret-key")
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(username):
    return User.query.filter(User.username == username).first()

login_manager.anonymous_user = lambda: None

try:
    locale.setlocale(locale.LC_ALL, 'en_US')
except:
    pass

from meta.blueprints.auth import auth
from meta.blueprints.profile import profile
from meta.blueprints.security import security
from meta.blueprints.keys import keys
from meta.blueprints.privacy import privacy
from meta.blueprints.oauth import oauth
from meta.blueprints.billing import billing
from meta.blueprints.api import api

app.register_blueprint(auth)
app.register_blueprint(profile)
app.register_blueprint(security)
app.register_blueprint(keys)
app.register_blueprint(privacy)
app.register_blueprint(oauth)
app.register_blueprint(billing)
app.register_blueprint(api)

@app.context_processor
def inject():
    return {
        'user': current_user,
        'owner': cfg("meta.sr.ht", "owner-name"),
        'owner_email': cfg("meta.sr.ht", "owner-email"),
    }
