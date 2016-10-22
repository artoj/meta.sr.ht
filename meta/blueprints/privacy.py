from flask import Blueprint, render_template, request, redirect
from flask_login import current_user
from meta.validation import Validation
from meta.common import loginrequired
from meta.types import User, PGPKey
from meta.db import db

privacy = Blueprint('privacy', __name__, template_folder='../../templates')

@privacy.route("/privacy")
@loginrequired
def privacy_GET():
    return render_template("privacy.html")

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
    db.commit()

    return redirect("/privacy")
