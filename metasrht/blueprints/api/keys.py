from flask import Blueprint, abort
from metasrht.types import SSHKey, PGPKey

keys = Blueprint('api.keys', __name__)

@keys.route("/api/ssh-key/<path:key_id>")
def ssh_key_GET(key_id):
    key = SSHKey.query.filter(SSHKey.b64_key == key_id).one_or_none()
    if not key:
        abort(404)
    return key.to_dict()

@keys.route("/api/pgp-key/<path:key_id>")
def pgp_key_GET(key_id):
    key = PGPKey.query.filter(PGPKey.key_id == key_id).one_or_none()
    if not key:
        abort(404)
    return key.to_dict()
