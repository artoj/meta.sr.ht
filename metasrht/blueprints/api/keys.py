from flask import Blueprint, abort
from metasrht.types import SSHKey, PGPKey

keys = Blueprint('api.keys', __name__)

@keys.route("/api/ssh-key/<path:key_id>")
def ssh_key_GET(key_id):
    # TODO: parse this and do it properly instead of being a dumb idiot
    key = SSHKey.query.filter(SSHKey.key.ilike(key_id)).one_or_none()
    if not key:
        abort(404)
    return key.to_dict()

@keys.route("/api/pgp-key/<path:key_id>")
def pgp_key_GET(key_id):
    key = PGPKey.query.filter(PGPKey.key_id == key_id).one_or_none()
    if not key:
        abort(404)
    return key.to_dict()
