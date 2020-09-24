from flask import Blueprint, Response, render_template, request, abort
from flask import redirect, url_for, session
from metasrht.blueprints.auth import validate_email
from metasrht.types import User, UserAuthFactor, FactorType
from srht.config import cfg
from srht.database import db
from srht.oauth import current_user, loginrequired, login_user
from srht.validation import Validation

profile = Blueprint('profile', __name__)

site_name = cfg("sr.ht", "site-name")

@profile.route("/~<username>.keys")
def user_keys_GET(username):
    user = User.query.filter(User.username == username).one_or_none()
    if not user:
        abort(404)
    resp = Response("\n".join(k.key.strip() for k in user.ssh_keys) + "\n")
    resp.headers["Content-Type"] = "text/plain"
    return resp

@profile.route("/~<username>.pgp")
def user_pgp_keys_GET(username):
    user = User.query.filter(User.username == username).one_or_none()
    if not user:
        abort(404)
    resp = Response("\n".join(k.key.strip() for k in user.pgp_keys) + "\n")
    resp.headers["Content-Type"] = "text/plain"
    return resp

@profile.route("/profile")
@loginrequired
def profile_GET():
    notice = session.pop("notice", None)
    return render_template("profile.html", notice=notice)

@profile.route("/profile", methods=["POST"])
@loginrequired
def profile_POST():
    valid = Validation(request)
    user = User.query.filter(User.id == current_user.id).one()

    email = valid.optional("email", user.email)
    email = email.strip()
    new_email = user.email != email
    if new_email:
        validate_email(valid, email)

    user.update(valid)
    if not valid.ok:
        return render_template("profile.html",
            **valid.kwargs), 400

    db.session.commit()
    login_user(user, set_cookie=True)
    if new_email:
        session["notice"] = "An email has been sent to your new address. Check your inbox to complete the change."
    return redirect(url_for(".profile_GET"))
