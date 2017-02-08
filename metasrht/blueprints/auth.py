from flask import Blueprint, render_template, abort, request, redirect, session
from flask_login import current_user, login_user, logout_user
from metasrht.types import User, UserType
from metasrht.types import UserAuthFactor, FactorType
from metasrht.email import send_email
from metasrht.audit import audit_log
from srht.validation import Validation
from srht.config import cfg
from srht.database import db
from pyotp import TOTP
import bcrypt

auth = Blueprint('auth', __name__)

site_name = cfg("meta.sr.ht", "site-name")

@auth.route("/")
def index():
    if current_user:
        return redirect("/profile")
    else:
        return render_template("register.html")

@auth.route("/register", methods=["POST"])
def register_POST():
    valid = Validation(request)

    username = valid.require("username", "Username")
    email = valid.require("email", "Email address")
    password = valid.require("password", "Password")

    if not valid.ok:
        return render_template("register.html", valid=valid)

    user = User.query.filter(User.username.ilike(username)).first()
    valid.expect(user is None, "This username is already in use.", "username")
    user = User.query.filter(User.email == email).first()
    valid.expect(user is None, "This email address is already in use.", "email")
    valid.expect(3 <= len(username) <= 256,
            "Username must be between 3 and 256 characters.", "username")
    valid.expect(len(email) <= 256,
            "Email must be no more than 256 characters.", "email")
    valid.expect(8 <= len(password) <= 512,
            "Password must be between 8 and 512 characters.", "password")

    if not valid.ok:
        return render_template("register.html", valid=valid), 400

    user = User(username.lower())
    user.email = email
    user.password = bcrypt.hashpw(password.encode('utf-8'),
            salt=bcrypt.gensalt()).decode('utf-8')

    send_email('confirm', user.email,
            'Confirm your {} account'.format(site_name),
            user=user)

    db.session.add(user)
    db.session.commit()
    login_user(user)
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
        login_user(user)
    return redirect("/")

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

    username = valid.require("username", "Username")
    password = valid.require("password", "Password")
    return_to = valid.optional("return_to", "/")

    if not valid.ok:
        return render_template("login.html", valid=valid), 400

    user = User.query.filter(User.username.ilike(username)).one_or_none()

    valid.expect(user is not None, "Username or password incorrect")

    if valid.ok:
        valid.expect(bcrypt.checkpw(password.encode('utf-8'),
            user.password.encode('utf-8')), "Username or password incorrect")

    if not valid.ok:
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

    login_user(user)
    audit_log("logged in")
    db.session.commit()
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
    if code:
        code = int(code)

    if not valid.ok:
        return render_template("totp-challenge.html",
            valid=valid,
            return_to=return_to)

    factor = UserAuthFactor.query.get(factors[0])
    secret = factor.secret.decode('utf-8')

    valid.expect(TOTP(secret).verify(code),
            'The code you entered is incorrect.', field='code')

    if not valid.ok:
        return render_template("totp-challenge.html",
            valid=valid,
            return_to=return_to)

    factors = factors[1:]
    if len(factors) != 0:
        return get_challenge(factors[0])

    del session['authorized_user']
    del session['extra_factors']
    del session['return_to']

    user = User.query.get(user_id)
    login_user(user)
    audit_log("logged in")
    db.session.commit()
    return redirect(return_to)

@auth.route("/logout")
def logout():
    if current_user:
        audit_log("logged out")
        logout_user()
        db.session.commit()
    return redirect("/login")
