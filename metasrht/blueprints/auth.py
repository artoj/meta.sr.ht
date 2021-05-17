from datetime import datetime
from dns.resolver import query as resolve
from flask import Blueprint, render_template, abort, request, redirect
from flask import url_for
from metasrht.audit import audit_log
from metasrht.auth import allow_registration, user_valid, prepare_user
from metasrht.auth import is_external_auth, set_user_password, set_user_email
from metasrht.auth.builtin import hash_password, check_password
from metasrht.auth_validation import validate_password
from metasrht.auth_validation import validate_username, validate_email
from metasrht.blueprints.security import metrics as security_metrics
from metasrht.email import send_email
from metasrht.totp import totp
from metasrht.types import User, UserType, Invite
from metasrht.types import UserAuthFactor, FactorType, PGPKey
from metasrht.webhooks import UserWebhook
from prometheus_client import Counter
from srht.config import cfg, get_global_domain
from srht.database import db
from srht.flask import csrf_bypass, session
from srht.oauth import current_user, login_user, logout_user
from srht.validation import Validation
from urllib.parse import urlparse

try:
    # This file is kept private to prevent spammers from reading it to
    # understand how to circumvent our spam prevention mechanisms.
    with open("/etc/abuse.py") as f:
        try:
            exec(f.read())
        except Exception as ex:
            print("Error loading abuse.py", ex)
            raise
except:
    def is_abuse(valid):
        return False

auth = Blueprint('auth', __name__)

site_name = cfg("sr.ht", "site-name")
onboarding_redirect = cfg("meta.sr.ht::settings", "onboarding-redirect")
site_key_id = cfg("mail", "pgp-key-id", None)

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

def validate_return_url(return_to):
    gdomain = get_global_domain("meta.sr.ht")
    parsed = urlparse(return_to)
    if parsed.netloc == "":
        return return_to
    netloc = parsed.netloc
    if "." in netloc:
        netloc = netloc[netloc.index("."):]
    if netloc == gdomain:
        return return_to
    return "/"

def issue_reset(user):
    rh = user.gen_reset_hash()
    db.session.commit()
    encrypt_key = None
    if user.pgp_key:
        encrypt_key = user.pgp_key.key
    send_email("reset_pw", user.email,
            f"Reset your password on {site_name}",
            headers={
                "From": f"{cfg('mail', 'smtp-from')}",
                "To": f"{user.username} <{user.email}>",
                "Reply-To": f"{cfg('sr.ht', 'owner-name')} <{cfg('sr.ht', 'owner-email')}>",
            }, user=user, encrypt_key=encrypt_key, reset=user.reset_hash)
    audit_log("password reset requested", user=user)
    return render_template("forgot.html", done=True)

@auth.route("/")
def index():
    if current_user:
        return redirect(url_for("profile.profile_GET"))
    return render_template("index.html")

@auth.route("/register")
def register():
    if current_user:
        return redirect("/")
    return render_template("register.html", site_key=site_key_id)

@auth.route("/register/<invite_hash>")
def register_invite(invite_hash):
    if current_user:
        return redirect("/")

    if is_external_auth():
        return render_template("register.html")

    invite = (Invite.query
        .filter(Invite.invite_hash == invite_hash)
        .filter(Invite.recipient_id == None)
    ).one_or_none()
    if not invite:
        abort(404)
    return render_template("register.html", site_key=site_key_id,
            invite_hash=invite_hash)


@csrf_bypass # for registration via sourcehut.org
@auth.route("/register", methods=["POST"])
def register_POST():
    valid = Validation(request)
    is_open = allow_registration()

    username = valid.require("username", friendly_name="Username")
    email = valid.require("email", friendly_name="Email address")
    password = valid.require("password", friendly_name="Password")
    invite_hash = valid.optional("invite_hash")
    pgp_key = valid.optional("pgp-key")
    invite = None

    valid.expect(not email or "@" in email,
            "Invalid email address", field="email")

    if email and "@" in email:
        _, domain = email.split("@")
        try:
            answer = resolve(domain, "MX")
            valid.expect("10minutemail.com" not in answer.response.to_text(),
                     "This email domain is blacklisted. Disposable email "
                     "addresses are prohibited by the terms of service - we "
                     "must be able to reach you at your account's primary "
                     "email address. Contact support if you believe this "
                     "domain was blacklisted in error.", "email")
        except:
            valid.expect(False, "Invalid email address", field="email")

    if not valid.ok:
        return render_template("register.html",
                is_open=(is_open or invite_hash is not None),
                site_key=site_key_id,
                **valid.kwargs), 400

    if is_abuse(valid):
        return redirect("/registered")

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

    validate_username(valid, username)
    validate_email(valid, email)
    validate_password(valid, password)

    if not valid.ok:
        return render_template("register.html",
                site_key=site_key_id,
                is_open=(is_open or invite_hash is not None),
                **valid.kwargs), 400

    allow_plus_in_email = valid.optional("allow-plus-in-email")
    if "+" in email and allow_plus_in_email != "yes":
        return render_template("register.html",
                site_key=site_key_id,
                is_open=(is_open or invite_hash is not None),
                **valid.kwargs), 400

    user = User(username)
    user.email = email
    user.password = hash_password(password)
    user.invites = cfg("meta.sr.ht::settings", "user-invites", default=0)

    pgp = None
    if site_key_id and pgp_key:
        pgp = PGPKey(user, valid)
        if not valid.ok:
            return render_template("register.html",
                site_key=site_key_id,
                is_open=(is_open or invite_hash is not None),
                **valid.kwargs), 400

    send_email("confirm", user.email,
            f"Confirm your {site_name} account",
            headers={
            "From": f"{cfg('mail', 'smtp-from')}",
                "To": f"{user.username} <{user.email}>",
                "Reply-To": f"{cfg('sr.ht', 'owner-name')} <{cfg('sr.ht', 'owner-email')}>",
            }, user=user, encrypt_key=pgp.key if pgp else None,
            confirmation=user.confirmation_hash)

    db.session.add(user)
    db.session.flush()
    audit_log("account registered", user=user)

    if invite:
        invite.recipient_id = user.id

    if pgp:
        user.pgp_key = pgp
        db.session.add(pgp)
        audit_log("pgp key added", f"Added PGP key {pgp.key_id}", user=user)
        audit_log("changed pgp key",
                f"Set default PGP key to {pgp.key_id}", user=user)

    metrics.meta_registrations.inc()
    print(f"New registration: {user.username} ({user.email})")
    db.session.commit()
    return redirect("/registered")

@auth.route("/registered")
def registered():
    return render_template("registered.html")

@auth.route("/confirm-account/<token>")
def confirm_account(token):
    user = User.query.filter(User.confirmation_hash == token).one_or_none()
    if not user:
        return render_template("already-confirmed.html",
                redir=onboarding_redirect)
    if user.new_email:
        user.confirmation_hash = None
        audit_log("email updated",
            "{} became {}".format(user.email, user.new_email), user=user)
        set_user_email(user, user.new_email)
        user.new_email = None
        db.session.commit()

        UserWebhook.deliver(UserWebhook.Events.profile_update, user.to_dict(),
                UserWebhook.Subscription.user_id == user.id)
        return redirect(url_for("profile.profile_GET"))
    elif user.user_type == UserType.unconfirmed:
        user.confirmation_hash = None
        user.user_type = UserType.active_non_paying
        audit_log("account confirmed", user=user)
        db.session.commit()
        login_user(user, set_cookie=True)
    if cfg("meta.sr.ht::billing", "enabled") == "yes":
        return redirect(url_for("billing.billing_initial_GET"))
    metrics.meta_confirmations.inc()
    print(f"Confirmed account: {user.username} ({user.email})")
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
        return render_template("login.html", **valid.kwargs), 400

    user_valid(valid, username, password)

    if not valid.ok:
        metrics.meta_logins_failed.inc()
        print(f"{datetime.utcnow()} Login attempt failed for {username}")
        return render_template("login.html",
            username=username,
            valid=valid)

    user = prepare_user(username)
    valid.expect(user.user_type != UserType.unconfirmed,
            "Your account is unconfirmed. Please check your inbox, or reach out to support if you did not receive an email.")
    valid.expect(user.user_type != UserType.suspended,
            f"Your account is suspended: {user.suspension_notice}. Contact support.")
    if not valid.ok:
        return render_template("login.html", **valid.kwargs), 400

    factors = (UserAuthFactor.query
        .filter(UserAuthFactor.user_id == user.id)).all()

    if any(factors):
        session['extra_factors'] = [f.id for f in factors]
        session['authorized_user'] = user.id
        session['challenge_type'] = 'login'
        session['return_to'] = return_to
        return get_challenge(factors[0])

    login_user(user, set_cookie=True)
    audit_log("logged in")
    print(f"Logged in account: {user.username} ({user.email})")
    db.session.commit()
    metrics.meta_logins_success.inc()
    return redirect(return_to)

@auth.route("/login/challenge/totp")
def totp_challenge_GET():
    user = session.get('authorized_user')
    if not user:
        return redirect("/login")
    challenge_type = session.get('challenge_type')
    return render_template("totp-challenge.html", challenge_type=challenge_type)

@auth.route("/login/challenge/totp", methods=["POST"])
def totp_challenge_POST():
    user_id = session.get('authorized_user')
    factors = session.get('extra_factors')
    challenge_type = session.get('challenge_type')
    return_to = session.get('return_to') or '/'
    if not user_id or not factors:
        return redirect("/login")
    valid = Validation(request)

    code = valid.require("code")
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

    user = User.query.get(user_id)
    if not valid.ok:
        print(f"{challenge_type} attempt failed (TOTP) for " +
            f"{user.username} ({user.email})")
        return render_template("totp-challenge.html",
            valid=valid, return_to=return_to)

    factors = factors[1:]
    if len(factors) != 0:
        return get_challenge(UserAuthFactor.query.get(factors[0]))

    session.pop('authorized_user', None)
    session.pop('extra_factors', None)
    session.pop('challenge_type', None)
    session.pop('return_to', None)

    if challenge_type == "login":
        login_user(user, set_cookie=True)
        audit_log("logged in")
        print(f"Logged in account: {user.username} ({user.email})")
        db.session.commit()
        metrics.meta_logins_success.inc()
        return_to = validate_return_url(return_to)
        return redirect(return_to)
    elif challenge_type == "reset":
        return issue_reset(user)
    elif challenge_type == "disable_totp":
        db.session.delete(factor)
        audit_log("Disable TOTP", details="Disabled two-factor authentication",
                email=True, subject=f"TOTP has been disabled for your {cfg('sr.ht', 'site-name')} account",
                email_details="2FA via TOTP was disabled")
        db.session.commit()
        security_metrics.meta_totp_disabled.inc()
        return redirect(return_to)
    else:
        raise NotImplemented

@auth.route("/login/challenge/totp-recovery")
def totp_recovery_GET():
    user = session.get('authorized_user')
    if not user:
        return redirect("/login")
    factors = session.get('extra_factors')
    factor = UserAuthFactor.query.get(factors[0])
    supported = factor.extra is not None
    return render_template("totp-recovery.html", supported=supported)

@auth.route("/login/challenge/totp-recovery", methods=["POST"])
def totp_recovery_POST():
    user_id = session.get('authorized_user')
    factors = session.get('extra_factors')
    challenge_type = session.get('challenge_type')
    return_to = session.get('return_to') or '/'
    if not user_id or not factors:
        return redirect("/login")
    valid = Validation(request)

    code = valid.require('recovery-code')
    if not valid.ok:
        return render_template("totp-recovery.html",
            return_to=return_to, **valid.kwargs)

    factor = UserAuthFactor.query.get(factors[0])
    is_valid = False
    for h in factor.extra:
        if check_password(code, h):
            is_valid = True
            break
    valid.expect(is_valid, "Incorrect recovery code", field="recovery-code")
    if not valid.ok:
        return render_template("totp-recovery.html",
            return_to=return_to, **valid.kwargs)

    user = User.query.get(user_id)

    db.session.delete(factor)
    audit_log("TOTP recovery code used", user=user, email=True,
            subject=f"A recovery code was used for your {cfg('sr.ht', 'site-name')} account",
            email_details="Two-factor authentication recovery code used")
    session["notice"] = "TOTP has been disabled for your account."
    db.session.commit()

    factors = factors[1:]
    if len(factors) != 0:
        return get_challenge(UserAuthFactor.query.get(factors[0]))

    session.pop('authorized_user', None)
    session.pop('extra_factors', None)
    session.pop('return_to', None)
    session.pop('challenge_type', None)

    if challenge_type == "login":
        login_user(user, set_cookie=True)
        audit_log("logged in")
        print(f"Logged in account: {user.username} ({user.email})")
        db.session.commit()
        metrics.meta_logins_success.inc()
        return_to = validate_return_url(return_to)
        return redirect(return_to)
    elif challenge_type == "reset":
        return issue_reset(user)
    elif challenge_type == "disable_totp":
        security_metrics.meta_totp_disabled.inc()
        return redirect(return_to)
    else:
        raise NotImplemented

@auth.route("/logout")
def logout():
    if current_user:
        audit_log("logged out")
        logout_user()
        db.session.commit()
        metrics.meta_logouts.inc()
    if request.args.get("return_to"):
        return_to = validate_return_url(request.args["return_to"])
        return redirect(return_to)
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
    valid.expect(not user or user.user_type != UserType.admin,
            "You can't reset the password of an admin.")
    valid.expect(not user or user.user_type != UserType.unconfirmed,
            f"Your account has not been confirmed. Please contact support via {cfg('sr.ht', 'owner-email')} if you did not receive a confirmation email.")
    if not valid.ok:
        return render_template("forgot.html", **valid.kwargs)

    factors = (UserAuthFactor.query
        .filter(UserAuthFactor.user_id == user.id)).all()
    if any(factors):
        session['extra_factors'] = [f.id for f in factors]
        session['authorized_user'] = user.id
        session['challenge_type'] = 'reset'
        return get_challenge(factors[0])

    return issue_reset(user)

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
    validate_password(valid, password)
    if not valid.ok:
        return render_template("reset.html", valid=valid)
    set_user_password(user, password)
    audit_log("password reset", user=user, email=True,
            subject=f"Your {cfg('sr.ht', 'site-name')} password has been reset",
            email_details="Account password reset")
    login_user(user, set_cookie=True)
    print(f"Reset password: {user.username} ({user.email})")
    metrics.meta_pw_resets.inc()
    return redirect("/")
