from flask import Blueprint, render_template, request, redirect, abort
from metasrht.audit import audit_log
from metasrht.types import SSHKey, PGPKey
from metasrht.types import User, UserAuthFactor, FactorType
from metasrht.webhooks import UserWebhook
from srht.config import cfg
from srht.database import db
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
    user = User.query.get(current_user.id)
    valid = Validation(request)
    key = SSHKey(user, valid)
    if not valid.ok:
        return render_template("keys.html",
            current_user=user, **valid.kwargs)
    db.session.add(key)
    db.session.commit()
    audit_log("SSH key added",
            details=f"Fingerprint {key.fingerprint}",
            email=True,
            subject=f"An SSH key was added to your {cfg('sr.ht', 'site-name')} account",
            email_details=f"SSH key {key.fingerprint} added")
    return redirect("/keys")

@keys.route("/keys/delete-ssh/<int:key_id>", methods=["POST"])
@loginrequired
def ssh_keys_delete(key_id):
    key = SSHKey.query.get(key_id)
    if not key or key.user_id != current_user.id:
        abort(404)
    key.delete()
    db.session.commit()
    audit_log("SSH key removed",
            details=f"Fingerprint {key.fingerprint}",
            email=True,
            subject=f"An SSH key was removed from your {cfg('sr.ht', 'site-name')} account",
            email_details=f"SSH key {key.fingerprint} removed")
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
