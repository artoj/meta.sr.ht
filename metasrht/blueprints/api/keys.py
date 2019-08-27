from flask import Blueprint, abort, request
from srht.crypto import verify_request_signature
from srht.database import db
from metasrht.types import SSHKey, PGPKey
from datetime import datetime

keys = Blueprint('api.keys', __name__)

@keys.route("/api/ssh-key/<path:key_id>")
def ssh_key_GET(key_id):
    # TODO: parse this and do it properly instead of being a dumb idiot
    key = SSHKey.query.filter(SSHKey.key.ilike("%"+key_id+"%")).one_or_none()
    if not key:
        abort(404)
    return key.to_dict()

@keys.route("/api/ssh-key/<path:key_id>", methods=["POST"])
def ssh_key_PUT(key_id):
    verify_request_signature(request)
    key = SSHKey.query.filter(SSHKey.b64_key == key_id).one_or_none()
    if not key:
        abort(404)
    key.last_used = datetime.utcnow()
    db.session.commit()
    return key.to_dict()

@keys.route("/api/pgp-key/<path:key_id>")
def pgp_key_GET(key_id):
    key = PGPKey.query.filter(PGPKey.key_id == key_id).one_or_none()
    if not key:
        abort(404)
    return key.to_dict()
