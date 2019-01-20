from flask import Blueprint, render_template, abort, request, redirect, session
from flask import url_for
from flask_login import current_user, login_user, logout_user
from metasrht.types import User, UserType, Invite
from metasrht.types import UserAuthFactor, FactorType
from metasrht.audit import audit_log
from metasrht.blacklist import username_blacklist
from metasrht.email import send_email
from metasrht.totp import totp
from prometheus_client import Counter
from srht.validation import Validation
from srht.config import cfg
from srht.database import db
from datetime import datetime
import bcrypt
import re

auth = Blueprint('auth', __name__)

site_name = cfg("sr.ht", "site-name")
onboarding_redirect = cfg("meta.sr.ht::settings", "onboarding-redirect")

metrics = type("metrics", tuple(), {
    c.describe()[0].name: c
    for c in [
        Counter("meta_registrations", "Number of new user registrations"),
        Counter("meta_confirmations", "Number of account confirmations"),
        Counter("meta_logins_failed", "Number of failed logins"),
        Counter("meta_logins_success", "Number of successful logins"),
        Counter("meta_logouts", "Number of sessions logged out"),
        Counter("meta_pw_resets", "Number of password resets completed"),
    ]
})

@auth.route("/")
def index():
    is_open = cfg("meta.sr.ht::settings", "registration") == "yes"
    return render_template("index.html", is_open=is_open)

@auth.route("/register")
def register():
    if current_user:
        return redirect("/")
    is_open = cfg("meta.sr.ht::settings", "registration") == "yes"
    return render_template("register.html", is_open=is_open)

@auth.route("/register/<invite_hash>")
def register_invite(invite_hash):
    if current_user:
        return redirect("/")
    invite = (Invite.query
        .filter(Invite.invite_hash == invite_hash)
        .filter(Invite.recipient_id == None)
    ).one_or_none()
    if not invite:
        abort(404)
    return render_template("register.html",
            is_open=True, invite_hash=invite_hash)

@auth.route("/register", methods=["POST"])
def register_POST():
    valid = Validation(request)
    is_open = cfg("meta.sr.ht::settings", "registration") == "yes"

    username = valid.require("username", friendly_name="Username")
    email = valid.require("email", friendly_name="Email address")
    password = valid.require("password", friendly_name="Password")
    invite_hash = valid.optional("invite_hash")
    invite = None

    if not valid.ok:
        return render_template("register.html",
                is_open=(is_open or invite_hash is not None),
                **valid.kwargs), 400

    if not is_open:
        if not invite_hash:
            abort(401)
        else:
            invite = (Invite.query
                .filter(Invite.invite_hash == invite_hash)
                .filter(Invite.recipient_id == None)
            ).one_or_none()
            if not invite:
                abort(401)

    email = email.strip()
    user = User.query.filter(User.username == username).first()
    valid.expect(user is None, "This username is already in use.", "username")
    user = User.query.filter(User.email == email).first()
    valid.expect(user is None, "This email address is already in use.", "email")
    valid.expect(2 <= len(username) <= 30,
            "Username must contain between 2 and 30 characters.", "username")
    valid.expect(re.match("^[a-z_]", username),
            "Username must start with a lowercase letter or underscore.",
            "username")
    valid.expect(re.match("^[a-z0-9_]+$", username),
            "Username may contain only lowercase letters, numbers and "
            "underscores", "username")
    valid.expect(username not in username_blacklist,
            "This username is not available", "username")
    valid.expect(len(email) <= 256,
            "Email must be no more than 256 characters.", "email")
    valid.expect(8 <= len(password) <= 512,
            "Password must be between 8 and 512 characters.", "password")

    if not valid.ok:
        return render_template("register.html",
                is_open=(is_open or invite_hash is not None),
                **valid.kwargs), 400

    user = User(username)
    user.email = email
    user.password = bcrypt.hashpw(password.encode('utf-8'),
            salt=bcrypt.gensalt()).decode('utf-8')
    user.invites = cfg("meta.sr.ht::settings", "user-invites", default=0)

    send_email('confirm', user.email,
            'Confirm your {} account'.format(site_name),
            headers={
                "From": f"{cfg('sr.ht', 'owner-name')} <outgoing@sr.ht>",
                "To": "{} <{}>".format(user.username ,user.email),
                "Reply-To": f"{cfg('sr.ht', 'owner-name')} <{cfg('sr.ht', 'owner-email')}>",
            }, user=user)

    db.session.add(user)
    if invite:
        db.session.flush()
        invite.recipient_id = user.id
    metrics.meta_registrations.inc()
    db.session.commit()
    return redirect("/registered")

@auth.route("/registered")
def registered():
    return render_template("registered.html")

@auth.route("/confirm-account/<token>")
def confirm_account(token):
    user = User.query.filter(User.confirmation_hash == token).one_or_none()
    if not user:
        abort(404)
    if user.new_email:
        user.confirmation_hash = None
        audit_log("email updated",
            "{} became {}".format(user.email, user.new_email))
        user.email = user.new_email
        user.new_email = None
        db.session.commit()
    elif user.user_type == UserType.unconfirmed:
        user.confirmation_hash = None
        user.user_type = UserType.active_non_paying
        audit_log("account created")
        db.session.commit()
        login_user(user, remember=True)
    if cfg("meta.sr.ht::billing", "enabled") == "yes":
        return redirect(url_for("billing.billing_initial_GET"))
    metrics.meta_confirmations.inc()
    return redirect(onboarding_redirect)

@auth.route("/login")
def login_GET():
    if current_user:
        return redirect("/")
    return_to = request.args.get('return_to')
    return render_template("login.html", return_to=return_to)

def get_challenge(factor):
    if factor.factor_type == FactorType.totp:
        return redirect("/login/challenge/totp")
    abort(500)

@auth.route("/login", methods=["POST"])
def login_POST():
    if current_user:
        return redirect("/")
    valid = Validation(request)

    username = valid.require("username", friendly_name="Username")
    password = valid.require("password", friendly_name="Password")
    return_to = valid.optional("return_to", "/")

    if not valid.ok:
        return render_template("login.html", valid=valid), 400

    user = User.query.filter(User.username == username.lower()).one_or_none()

    valid.expect(user is not None, "Username or password incorrect")

    if valid.ok:
        valid.expect(bcrypt.checkpw(password.encode('utf-8'),
            user.password.encode('utf-8')), "Username or password incorrect")

    if not valid.ok:
        metrics.meta_logins_failed.inc()
        return render_template("login.html",
            username=username,
            valid=valid)

    factors = UserAuthFactor.query \
        .filter(UserAuthFactor.user_id == user.id).all()

    if any(factors):
        session['extra_factors'] = [f.id for f in factors]
        session['authorized_user'] = user.id
        session['return_to'] = return_to
        return get_challenge(factors[0])

    login_user(user, remember=True)
    audit_log("logged in")
    db.session.commit()
    metrics.meta_logins_success.inc()
    return redirect(return_to)

@auth.route("/login/challenge/totp")
def totp_challenge_GET():
    user = session.get('authorized_user')
    if not user:
        return redirect("/login")
    return render_template("totp-challenge.html")

@auth.route("/login/challenge/totp", methods=["POST"])
def totp_challenge_POST():
    user_id = session.get('authorized_user')
    factors = session.get('extra_factors')
    return_to = session.get('return_to') or '/'
    if not user_id or not factors:
        return redirect("/login")
    valid = Validation(request)

    code = valid.require('code')

    if not valid.ok:
        return render_template("totp-challenge.html",
            return_to=return_to, valid=valid)
    code = code.replace(" ", "")
    try:
        code = int(code)
    except:
        valid.error(
                "This TOTP code is invalid (expected a number)", field="code")
    if not valid.ok:
        return render_template("totp-challenge.html",
            return_to=return_to, valid=valid)

    factor = UserAuthFactor.query.get(factors[0])
    secret = factor.secret.decode('utf-8')

    valid.expect(totp(secret, code),
            'The code you entered is incorrect.', field='code')

    if not valid.ok:
        return render_template("totp-challenge.html",
            valid=valid, return_to=return_to)

    factors = factors[1:]
    if len(factors) != 0:
        return get_challenge(factors[0])

    del session['authorized_user']
    del session['extra_factors']
    del session['return_to']

    user = User.query.get(user_id)
    login_user(user, remember=True)
    audit_log("logged in")
    db.session.commit()
    metrics.meta_logins_success.inc()
    return redirect(return_to)

@auth.route("/logout")
def logout():
    if current_user:
        audit_log("logged out")
        logout_user()
        db.session.commit()
        metrics.meta_logouts.inc()
    return redirect("/login")

@auth.route("/forgot")
def forgot():
    return render_template("forgot.html")

@auth.route("/forgot", methods=["POST"])
def forgot_POST():
    valid = Validation(request)
    email = valid.require("email", friendly_name="Email")
    if not valid.ok:
        return render_template("forgot.html", **valid.kwargs)
    user = User.query.filter(User.email == email).first()
    valid.expect(user, "No account found with this email address.")
    if not valid.ok:
        return render_template("forgot.html", **valid.kwargs)
    factors = (UserAuthFactor.query
        .filter(UserAuthFactor.user_id == user.id)
    ).all()
    valid.expect(not any(f for f in factors if f.factor_type in [
        FactorType.totp, FactorType.u2f
    ]), "This account has two-factor authentication enabled, contact support.")
    if not valid.ok:
        return render_template("forgot.html", **valid.kwargs)
    rh = user.gen_reset_hash()
    db.session.commit()
    send_email('reset_pw', user.email,
            'Reset your password on {}'.format(site_name),
            headers={
                "From": f"{cfg('sr.ht', 'owner-name')} <outgoing@sr.ht>",
                "To": "{} <{}>".format(user.username ,user.email),
                "Reply-To": f"{cfg('sr.ht', 'owner-name')} <{cfg('sr.ht', 'owner-email')}>",
            }, user=user)
    audit_log("password reset requested", user=user)
    return render_template("forgot.html", done=True)

@auth.route("/reset-password/<token>")
def reset_GET(token):
    user = User.query.filter(User.reset_hash == token).first()
    if not user:
        abort(404)
    if user.reset_expiry < datetime.utcnow():
        abort(404)
    return render_template("reset.html")

@auth.route("/reset-password/<token>", methods=["POST"])
def reset_POST(token):
    user = User.query.filter(User.reset_hash == token).first()
    if not user:
        abort(404)
    if user.reset_expiry < datetime.utcnow():
        abort(404)
    valid = Validation(request)
    password = valid.require("password", friendly_name="Password")
    if not valid.ok:
        return render_template("reset.html", valid=valid)
    valid.expect(8 <= len(password) <= 512,
            "Password must be between 8 and 512 characters.", "password")
    if not valid.ok:
        return render_template("reset.html", valid=valid)
    user.password = bcrypt.hashpw(password.encode('utf-8'),
            salt=bcrypt.gensalt()).decode('utf-8')
    audit_log("password reset", user=user)
    db.session.commit()
    login_user(user, remember=True)
    metrics.meta_pw_resets.inc()
    return redirect("/")
