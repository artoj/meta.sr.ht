from flask import Blueprint, render_template, request, redirect, abort
from flask_login import current_user
from pyotp import TOTP
from metasrht.common import loginrequired
from metasrht.types import User, UserAuthFactor, FactorType
from metasrht.types import AuditLogEntry
from metasrht.audit import audit_log
from metasrht.qrcode import gen_qr
from srht.validation import Validation, valid_url
from srht.config import cfg
from srht.database import db
import base64
import os

security = Blueprint('security', __name__)

site_name = cfg("meta.sr.ht", "site-name")

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
    db.session.add(factor)
    audit_log("enabled two factor auth", 'Enabled TOTP')
    db.session.commit()
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
    db.session.delete(factor)
    audit_log("disabled two factor auth", 'Disabled TOTP')
    db.session.commit()
    return redirect("/security")
