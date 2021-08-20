from flask import Blueprint, render_template, request, redirect, abort
from metasrht.audit import audit_log
from metasrht.types import SSHKey, PGPKey
from metasrht.types import User, UserAuthFactor, FactorType
from metasrht.webhooks import UserWebhook
from srht.config import cfg
from srht.database import db
from srht.graphql import exec_gql
from srht.oauth import current_user, loginrequired
from srht.validation import Validation, valid_url

keys = Blueprint('keys', __name__)

@keys.route("/keys")
@loginrequired
def keys_GET():
    return render_template("keys.html")

@keys.route("/keys/ssh-keys", methods=["GET"])
@loginrequired
def ssh_keys_GET():
    return render_template("keys.html")

@keys.route("/keys/ssh-keys", methods=["POST"])
@loginrequired
def ssh_keys_POST():
    valid = Validation(request)
    resp = exec_gql("meta.sr.ht", """
    mutation CreateSSHKey($key: String!) {
        createSSHKey(key: $key) { id }
    }
    """, valid=valid, key=valid.source.get("key", ""))
    if not valid.ok:
        return render_template("keys.html", **valid.kwargs), 400
    return redirect("/keys")

@keys.route("/keys/delete-ssh/<int:key_id>", methods=["POST"])
@loginrequired
def ssh_keys_delete(key_id):
    resp = exec_gql("meta.sr.ht", """
    mutation DeleteSSHKey($key: Int!) {
        deleteSSHKey(id: $key) { id }
    }
    """, key=key_id)
    return redirect("/keys")

@keys.route("/keys/pgp-keys")
@loginrequired
def pgp_keys_GET():
    return render_template("keys.html")

@keys.route("/keys/pgp-keys", methods=["POST"])
@loginrequired
def pgp_keys_POST():
    user = User.query.get(current_user.id)
    valid = Validation(request)
    key = PGPKey(user, valid)
    if not valid.ok:
        return render_template("keys.html",
            current_user=user, **valid.kwargs)
    db.session.add(key)
    db.session.commit()
    audit_log("PGP key added",
            details=f"Key ID {key.key_id}",
            email=True,
            subject=f"A PGP key was added to your {cfg('sr.ht', 'site-name')} account",
            email_details=f"PGP key {key.key_id} added")
    return redirect("/keys")

@keys.route("/keys/delete-pgp/<int:key_id>", methods=["POST"])
@loginrequired
def pgp_keys_delete(key_id):
    user = User.query.get(current_user.id)
    key = PGPKey.query.get(key_id)
    if not key or key.user_id != user.id:
        abort(404)
    if key.id == user.pgp_key_id:
        return render_template("keys.html",
                current_user=user, tried_to_delete_key_in_use=True), 400
    key.delete()
    db.session.commit()
    audit_log("PGP key removed",
            details=f"Key ID {key.key_id}",
            email=True,
            subject=f"A PGP key was removed from your {cfg('sr.ht', 'site-name')} account",
            email_details=f"PGP key {key.key_id} removed")
    return redirect("/keys")
