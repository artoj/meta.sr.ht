from flask import Blueprint, Response, render_template, request, redirect
from flask_login import current_user
from meta.audit import audit_log
from meta.validation import Validation
from meta.common import loginrequired
from meta.types import User, PGPKey, EventType
from meta.email import send_email
from meta.config import _cfg
from meta.db import db

privacy = Blueprint('privacy', __name__, template_folder='../../templates')

@privacy.route("/privacy")
@loginrequired
def privacy_GET():
    return render_template("privacy.html")

@privacy.route("/privacy/pubkey")
def privacy_pubkey_GET():
    with open(_cfg("sr.ht", "pgp-pubkey"), "r") as f:
        pubkey = f.read()
    return Response(pubkey, mimetype="text/plain")

@privacy.route("/privacy", methods=["POST"])
@loginrequired
def privacy_POST():
    valid = Validation(request)

    key_id = valid.require("pgp-key")
    key_id = key_id if key_id != "null" else None
    key = None

    if key_id:
        key = PGPKey.query.get(int(key_id))
        valid.expect(key.user_id == current_user.id, "Invalid PGP key")

    if not valid.ok:
        return redirect("/privacy")

    user = User.query.get(current_user.id)
    user.pgp_key = key
    audit_log(EventType.changed_pgp_key,
            "Set default PGP key to {}".format(key.key_id if key else None))
    db.commit()

    return redirect("/privacy")

@privacy.route("/privacy/test-email", methods=["POST"])
@loginrequired
def privacy_testemail_POST():
    user = User.query.get(current_user.id)
    send_email("test", user.email, "Test email",
            encrypt_key=user.pgp_key,
            site_key=_cfg("sr.ht", "pgp-key-id"))
    return redirect("/privacy")
