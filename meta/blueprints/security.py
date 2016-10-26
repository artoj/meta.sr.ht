from flask import Blueprint, render_template, request, redirect, abort
from flask_login import current_user
from pyotp import TOTP
from meta.common import loginrequired
from meta.types import User, UserAuthFactor, FactorType
from meta.types import AuditLogEntry
from meta.validation import Validation, valid_url
from meta.config import cfg
from meta.audit import audit_log
from meta.qrcode import gen_qr
from meta.db import db
import base64
import os

security = Blueprint('security', __name__, template_folder='../../templates')

@security.route("/security")
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

@security.route("/security/audit/log")
@loginrequired
def security_audit_log_GET():
    audit_log = AuditLogEntry.query \
        .order_by(AuditLogEntry.created.desc()).all()
    return render_template("audit-log.html", audit_log=audit_log)

def totp_get_qrcode(secret):
    site_name = cfg("sr.ht", "site-name")
    return gen_qr("otpauth://totp/{}:{}?secret={}&issuer={}".format(
        site_name, "{} <{}>".format(current_user.username,
            current_user.email), secret, site_name))

@security.route("/security/totp/enable")
@loginrequired
def security_totp_enable_GET():
    secret = base64.b32encode(os.urandom(10)).decode('utf-8')
    return render_template("totp-enable.html",
        qrcode=totp_get_qrcode(secret),
        secret=secret)

@security.route("/security/totp/enable", methods=["POST"])
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
    audit_log("enabled two factor auth", 'Enabled TOTP')
    db.commit()
    return redirect("/security")

@security.route("/security/totp/disable", methods=["POST"])
@loginrequired
def security_totp_disable_POST():
    factor = UserAuthFactor.query \
            .filter(UserAuthFactor.user_id == current_user.id)\
            .filter(UserAuthFactor.factor_type == FactorType.totp)\
            .one_or_none()
    if not factor:
        return redirect("/security")
    db.delete(factor)
    audit_log("disabled two factor auth", 'Disabled TOTP')
    db.commit()
    return redirect("/security")
