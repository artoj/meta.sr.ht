from flask import Blueprint, render_template, request, redirect, abort
from flask_login import current_user
from pyotp import TOTP
from meta.common import loginrequired
from meta.types import User, EventType, UserAuthFactor, FactorType
from meta.types import AuditLogEntry
from meta.validation import Validation, valid_url
from meta.email import send_email
from meta.config import _cfg
from meta.audit import audit_log
from meta.qrcode import gen_qr
from meta.db import db
import base64
import os

profile = Blueprint('profile', __name__, template_folder='../../templates')

@profile.route("/profile")
@loginrequired
def profile_GET():
    return render_template("profile.html")

@profile.route("/profile", methods=["POST"])
@loginrequired
def profile_POST():
    valid = Validation(request)

    user = User.query.filter(User.id == current_user.id).one()

    email = valid.optional("email", user.email)
    url = valid.optional("url", user.url)
    location = valid.optional("location", user.location)
    bio = valid.optional("bio", user.bio)

    valid.expect(not url or 0 <= len(url) <= 256,
            "URL must fewer than 256 characters.", "url")
    valid.expect(not url or valid_url(url),
            "URL must be a valid http or https URL", "url")
    valid.expect(not location or 0 <= len(location) <= 256,
            "Location must fewer than 256 characters.", "location")
    valid.expect(not bio or 0 <= len(bio) <= 4096,
            "Bio must fewer than 4096 characters.", "bio")

    if not valid.ok:
        return render_template("profile.html",
            email=email, url=url, location=location, bio=bio,
            valid=valid), 400

    user.url = url
    user.location = location
    user.bio = bio

    new_email = user.email != email
    if new_email:
        user.new_email = email
        user.gen_confirmation_hash()
        send_email('update_email_old', user.email,
            'Your {} email address is changing'.format(
                _cfg("sr.ht", "site-name")),
            new_email=email)
        send_email('update_email_new', user.new_email,
            'Confirm your {} email address change'.format(
                _cfg("sr.ht", "site-name")),
            new_email=email)

    audit_log(EventType.updated_profile)
    db.commit()

    return render_template("profile.html", new_email=new_email)

@profile.route("/security")
@loginrequired
def security_GET():
    totp = UserAuthFactor.query \
        .filter(UserAuthFactor.user_id == current_user.id) \
        .filter(UserAuthFactor.factor_type == FactorType.totp) \
        .one_or_none()
    email = UserAuthFactor.query \
        .filter(UserAuthFactor.user_id == current_user.id) \
        .filter(UserAuthFactor.factor_type == FactorType.email) \
        .one_or_none()
    audit_log = AuditLogEntry.query \
        .order_by(AuditLogEntry.created.desc()) \
        .limit(15)
    return render_template("security.html",
        audit_log=audit_log,
        totp=totp,
        email=email)

@profile.route("/security/audit/forget/<entry_id>", methods=["POST"])
@loginrequired
def security_forget_event(entry_id):
    event = AuditLogEntry.query \
        .filter(AuditLogEntry.user_id == current_user.id) \
        .filter(AuditLogEntry.id == entry_id).one_or_none()
    if not event:
        abort(404)
    db.delete(event)
    db.commit()
    return redirect("/security")

def totp_get_qrcode(secret):
    site_name = _cfg("sr.ht", "site-name")
    return gen_qr("otpauth://totp/{}:{}?secret={}&issuer={}".format(
        site_name, "{} <{}>".format(current_user.username,
            current_user.email), secret, site_name))

@profile.route("/security/totp/enable")
@loginrequired
def security_totp_enable_GET():
    secret = base64.b32encode(os.urandom(10)).decode('utf-8')
    return render_template("totp-enable.html",
        qrcode=totp_get_qrcode(secret),
        secret=secret)

@profile.route("/security/totp/enable", methods=["POST"])
@loginrequired
def security_totp_enable_POST():
    valid = Validation(request)

    secret = valid.require("secret")
    code = valid.require("code")
    
    if not valid.ok:
        return render_template("totp-enable.html",
            qrcode=get_qrcode(),
            secret=secret,
            valid=valid), 400

    valid.expect(TOTP(secret).verify(int(code)),
            "The code you entered is incorrect.", field="code")

    if not valid.ok:
        return render_template("totp-enable.html",
            qrcode=get_qrcode(),
            secret=secret,
            valid=valid), 400

    factor = UserAuthFactor(current_user, FactorType.totp)
    factor.secret = secret.encode('utf-8')
    db.add(factor)
    audit_log(EventType.enabled_two_factor, 'Enabled TOTP')
    db.commit()
    return redirect("/security")

@profile.route("/oauth")
@loginrequired
def oauth():
    return render_template("oauth.html")

@profile.route("/keys")
@loginrequired
def keys():
    return render_template("keys.html")

@profile.route("/billing")
@loginrequired
def billing():
    return render_template("billing.html")
