from flask import Blueprint, render_template, request, redirect, abort
from flask_login import current_user
from metasrht.audit import audit_log
from metasrht.types import SSHKey, PGPKey
from metasrht.types import User, UserAuthFactor, FactorType
from metasrht.webhooks import UserWebhook
from srht.database import db
from srht.flask import loginrequired
from srht.validation import Validation, valid_url

keys = Blueprint('keys', __name__)

@keys.route("/keys")
@loginrequired
def keys_GET():
    return render_template("keys.html")

@keys.route("/keys/ssh-keys", methods=["POST"])
@loginrequired
def ssh_keys_POST():
    user = User.query.get(current_user.id)
    valid = Validation(request)
    key = SSHKey(user, valid)
    if not valid.ok:
        return render_template("keys.html",
            current_user=user, **valid.kwargs)
    db.session.add(key)
    db.session.commit()
    return redirect("/keys")

@keys.route("/keys/delete-ssh/<int:key_id>", methods=["POST"])
@loginrequired
def ssh_keys_delete(key_id):
    key = SSHKey.query.get(key_id)
    if not key or key.user_id != current_user.id:
        abort(404)
    key.delete()
    db.session.commit()
    return redirect("/keys")

@keys.route("/keys/pgp-keys", methods=["POST"])
@loginrequired
def pgp_keys_POST():
    user = User.query.get(current_user.id)
    valid = Validation(request)
    pgp = PGPKey(user, valid)
    if not valid.ok:
        return render_template("keys.html",
            current_user=user, **valid.kwargs)
    db.session.add(pgp)
    db.session.commit()
    return redirect("/keys")

@keys.route("/keys/delete-pgp/<key_id>", methods=["POST"])
@loginrequired
def pgp_keys_delete(key_id):
    user = User.query.get(current_user.id)
    key = PGPKey.query.get(int(key_id))
    if not key or key.user_id != user.id:
        abort(404)
    audit_log("pgp key deleted", 'Deleted PGP key {}'.format(key.key_id))
    db.session.delete(key)
    db.session.commit()
    UserWebhook.deliver(UserWebhook.Events.pgp_key_remove,
            { "id": key_id }, UserWebhook.Subscription.user_id == user.id)
    return redirect("/keys")
