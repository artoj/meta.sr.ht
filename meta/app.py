from flask import Flask, render_template, request, g, Response, redirect, url_for
from flask.ext.login import LoginManager, current_user
from jinja2 import FileSystemLoader, ChoiceLoader

import random
import sys
import os
import locale

from meta.config import _cfg, _cfgi
from meta.database import db, init_db
from meta.objects import User
from meta.common import *

app = Flask(__name__)
app.secret_key = _cfg("server", "secret-key")
app.jinja_env.cache = None
init_db()
login_manager = LoginManager()
login_manager.init_app(app)

app.jinja_loader = ChoiceLoader([
    FileSystemLoader("overrides"),
    FileSystemLoader("templates"),
])

@login_manager.user_loader
def load_user(username):
    return User.query.filter(User.username == username).first()

login_manager.anonymous_user = lambda: None

try:
    locale.setlocale(locale.LC_ALL, 'en_US')
except:
    pass

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/security")
def security():
    return render_template("security.html")

@app.route("/oauth")
def oauth():
    return render_template("oauth.html")

@app.route("/git")
def git():
    return render_template("git.html")

if not app.debug:
    @app.errorhandler(500)
    def handle_500(e):
        # shit
        try:
            db.rollback()
            db.close()
        except:
            # shit shit
            sys.exit(1)
        return render_template("internal_error.html"), 500
    # Error handler
    if _cfg("mail", "error-to") != "":
        import logging
        from logging.handlers import SMTPHandler
        mail_handler = SMTPHandler((_cfg("mail", "smtp-host"), _cfg("mail", "smtp-port")),
           _cfg("mail", "error-from"),
           [_cfg("mail", "error-to")],
           'sr.ht application exception occured',
           credentials=(_cfg("mail", "smtp-user"), _cfg("mail", "smtp-password")))
        mail_handler.setLevel(logging.ERROR)
        app.logger.addHandler(mail_handler)

@app.errorhandler(404)
def handle_404(e):
    return render_template("not_found.html"), 404

@app.context_processor
def inject():
    return {
        'root': _cfg("server", "protocol") + "://" + _cfg("server", "domain"),
        'domain': _cfg("server", "domain"),
        'protocol': _cfg("server", "protocol"),
        'len': len,
        'any': any,
        'request': request,
        'locale': locale,
        'url_for': url_for,
        'user': current_user,
        'owner': _cfg("sr.ht", "owner-name"),
        'owner_email': _cfg("sr.ht", "owner-email"),
        '_cfg': _cfg
    }
