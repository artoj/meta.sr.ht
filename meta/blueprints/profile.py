from flask import Blueprint, render_template, request, redirect, abort
from flask_login import current_user
from pyotp import TOTP
from meta.common import loginrequired
from meta.types import User, EventType, UserAuthFactor, FactorType
from meta.types import AuditLogEntry, SSHKey, PGPKey
from meta.validation import Validation, valid_url
from meta.email import send_email
from meta.config import _cfg
from meta.audit import audit_log
from meta.qrcode import gen_qr
from meta.db import db
import sshpubkeys as ssh
import pgpy
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
    audit_log = AuditLogEntry.query \
        .order_by(AuditLogEntry.created.desc()) \
        .limit(15)
    return render_template("security.html",
        audit_log=audit_log,
        totp=totp)

@profile.route("/security/audit/log")
@loginrequired
def security_audit_log_GET():
    audit_log = AuditLogEntry.query \
        .order_by(AuditLogEntry.created.desc()).all()
    return render_template("audit-log.html", audit_log=audit_log)

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
            qrcode=totp_get_qrcode(secret),
            secret=secret,
            valid=valid), 400

    valid.expect(TOTP(secret).verify(int(code)),
            "The code you entered is incorrect.", field="code")

    if not valid.ok:
        return render_template("totp-enable.html",
            qrcode=totp_get_qrcode(secret),
            secret=secret,
            valid=valid), 400

    factor = UserAuthFactor(current_user, FactorType.totp)
    factor.secret = secret.encode('utf-8')
    db.add(factor)
    audit_log(EventType.enabled_two_factor, 'Enabled TOTP')
    db.commit()
    return redirect("/security")

@profile.route("/security/totp/disable", methods=["POST"])
@loginrequired
def security_totp_disable_POST():
    factor = UserAuthFactor.query \
            .filter(UserAuthFactor.user_id == current_user.id)\
            .filter(UserAuthFactor.factor_type == FactorType.totp)\
            .one_or_none()
    if not factor:
        return redirect("/security")
    db.delete(factor)
    audit_log(EventType.disabled_two_factor, 'Disabled TOTP')
    db.commit()
    return redirect("/security")

@profile.route("/keys")
@loginrequired
def keys():
    user = User.query.get(current_user.id)
    return render_template("keys.html", current_user=user)

@profile.route("/keys/ssh-keys", methods=["POST"])
@loginrequired
def ssh_keys_POST():
    user = User.query.get(current_user.id)
    valid = Validation(request)

    ssh_key = valid.require("ssh-key")
    if valid.ok:
        try:
            parsed_key = ssh.SSHKey(ssh_key)
            valid.expect(parsed_key.bits, "This is not a valid SSH key", "ssh-key")
        except:
            valid.error("This is not a valid SSH key", "ssh-key")
    if valid.ok:
        fingerprint = parsed_key.hash_md5()[4:]
        valid.expect(SSHKey.query\
            .filter(SSHKey.user_id == user.id) \
            .filter(SSHKey.fingerprint == fingerprint) \
            .count() == 0, "This is a duplicate key", "ssh-key")

    if not valid.ok:
        return render_template("keys.html",
            current_user=user,
            ssh_key=ssh_key,
            valid=valid)

    key = SSHKey(user, ssh_key, fingerprint, parsed_key.comment)
    db.add(key)
    audit_log(EventType.add_ssh_key, 'Added SSH key {}'.format(fingerprint))
    db.commit()
    return redirect("/keys")

@profile.route("/keys/delete-ssh/<key_id>", methods=["POST"])
@loginrequired
def ssh_keys_delete(key_id):
    user = User.query.get(current_user.id)
    key = SSHKey.query.get(int(key_id))
    if not key or key.user_id != user.id:
        abort(404)
    audit_log(EventType.deleted_ssh_key, 'Deleted SSH key {}'.format(key.fingerprint))
    db.delete(key)
    db.commit()
    return redirect("/keys")

@profile.route("/keys/pgp-keys", methods=["POST"])
@loginrequired
def pgp_keys_POST():
    user = User.query.get(current_user.id)
    valid = Validation(request)

    pgp_key = valid.require("pgp-key")
    if valid.ok:
        try:
            key = pgpy.PGPKey()
            key.parse(pgp_key.replace('\r', '').encode('utf-8'))
        except:
            valid.error("This is not a valid PGP key", "pgp-key")
    if valid.ok:
        valid.expect(PGPKey.query\
            .filter(PGPKey.user_id == user.id) \
            .filter(PGPKey.key_id == key.fingerprint)\
            .count() == 0, "This is a duplicate key", "pgp-key")
    if not valid.ok:
        return render_template("keys.html",
            current_user=user,
            pgp_key=pgp_key,
            valid=valid)

    pgp = PGPKey(user, pgp_key, key.fingerprint, key.userids[0].email)
    db.add(pgp)
    audit_log(EventType.add_pgp_key, 'Added PGP key {}'.format(key.fingerprint))
    db.commit()
    return redirect("/keys")

@profile.route("/keys/delete-pgp/<key_id>", methods=["POST"])
@loginrequired
def pgp_keys_delete(key_id):
    user = User.query.get(current_user.id)
    key = PGPKey.query.get(int(key_id))
    if not key or key.user_id != user.id:
        abort(404)
    audit_log(EventType.deleted_pgp_key, 'Deleted PGP key {}'.format(key.key_id))
    db.delete(key)
    db.commit()
    return redirect("/keys")

@profile.route("/oauth")
@loginrequired
def oauth():
    return render_template("oauth.html")

@profile.route("/billing")
@loginrequired
def billing():
    return render_template("billing.html")
