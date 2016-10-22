from flask import Blueprint, render_template, request, redirect, abort
from flask_login import current_user
from meta.common import loginrequired
from meta.types import User, EventType, UserAuthFactor, FactorType
from meta.types import SSHKey, PGPKey
from meta.validation import Validation, valid_url
from meta.audit import audit_log
from meta.db import db
import sshpubkeys as ssh
import pgpy

keys = Blueprint('keys', __name__, template_folder='../../templates')

@keys.route("/keys")
@loginrequired
def keys_GET():
    user = User.query.get(current_user.id)
    return render_template("keys.html", current_user=user)

@keys.route("/keys/ssh-keys", methods=["POST"])
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

@keys.route("/keys/delete-ssh/<key_id>", methods=["POST"])
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

@keys.route("/keys/pgp-keys", methods=["POST"])
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

@keys.route("/keys/delete-pgp/<key_id>", methods=["POST"])
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
