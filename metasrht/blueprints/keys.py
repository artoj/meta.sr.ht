from flask import Blueprint, render_template, request, redirect, abort
from flask_login import current_user
from jinja2 import Markup
from metasrht.types import User, UserAuthFactor, FactorType
from metasrht.types import SSHKey, PGPKey
from metasrht.audit import audit_log
from srht.database import db
from srht.flask import loginrequired
from srht.validation import Validation, valid_url
import sshpubkeys as ssh
import pgpy
import pgpy.constants

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

    ssh_key = valid.require("ssh-key")
    if valid.ok:
        try:
            parsed_key = ssh.SSHKey(ssh_key)
            valid.expect(parsed_key.bits,
                    "This is not a valid SSH key", "ssh-key")
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
    db.session.add(key)
    audit_log("ssh key added", 'Added SSH key {}'.format(fingerprint))
    db.session.commit()
    return redirect("/keys")

@keys.route("/keys/delete-ssh/<key_id>", methods=["POST"])
@loginrequired
def ssh_keys_delete(key_id):
    user = User.query.get(current_user.id)
    key = SSHKey.query.get(int(key_id))
    if not key or key.user_id != user.id:
        abort(404)
    audit_log("ssh key deleted", 'Deleted SSH key {}'.format(key.fingerprint))
    db.session.delete(key)
    db.session.commit()
    return redirect("/keys")

@keys.route("/keys/pgp-keys", methods=["POST"])
@loginrequired
def pgp_keys_POST():
    user = User.query.get(current_user.id)
    valid = Validation(request)

    pgp_key = valid.require("pgp-key")
    valid.expect(not pgp_key or len(pgp_key) < 32768,
            Markup("Maximum encoded key length is 32768 bytes. "
                "Try <br /><code>gpg --armor --export --export-options "
                "export-minimal</code><br /> to export a smaller key."),
            field="pgp-key")
    if valid.ok:
        try:
            key = pgpy.PGPKey()
            key.parse(pgp_key.replace('\r', '').encode('utf-8'))
        except:
            valid.error("This is not a valid PGP key", field="pgp-key")
        flags = key._get_key_flags()
        valid.expect(pgpy.constants.KeyFlags.EncryptCommunications in flags,
                "This key does not support encryption", field="pgp-key")
    if valid.ok:
        valid.expect(PGPKey.query\
            .filter(PGPKey.user_id == user.id) \
            .filter(PGPKey.key_id == key.fingerprint)\
            .count() == 0, "This is a duplicate key", field="pgp-key")
    if not valid.ok:
        return render_template("keys.html",
            current_user=user,
            pgp_key=pgp_key,
            valid=valid)

    pgp = PGPKey(user, pgp_key, key.fingerprint, key.userids[0].email)
    db.session.add(pgp)
    audit_log("pgp key added", 'Added PGP key {}'.format(key.fingerprint))
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
    return redirect("/keys")
