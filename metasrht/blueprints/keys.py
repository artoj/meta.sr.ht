from flask import Blueprint, render_template, request, redirect
from srht.graphql import exec_gql
from srht.oauth import current_user, loginrequired
from srht.validation import Validation

keys = Blueprint('keys', __name__)

@keys.route("/keys")
@loginrequired
def keys_GET():
    return render_template("keys.html")

@keys.route("/keys/ssh-keys", methods=["POST"])
@loginrequired
def ssh_keys_POST():
    valid = Validation(request)
    resp = exec_gql("meta.sr.ht", """
    mutation CreateSSHKey($key: String!) {
        createSSHKey(key: $key) { id }
    }
    """, valid=valid, key=valid.source.get("ssh-key", ""))
    if not valid.ok:
        # The GraphQL parameter is called key, but we call it ssh-key to
        # disambiguate from PGP keys, which are configured on the same page.
        for err in valid.errors:
            if err.field == "key":
                err.field = "ssh-key"
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

@keys.route("/keys/pgp-keys", methods=["POST"])
@loginrequired
def pgp_keys_POST():
    valid = Validation(request)
    resp = exec_gql("meta.sr.ht", """
    mutation CreatePGPKey($key: String!) {
        createPGPKey(key: $key) { id }
    }
    """, valid=valid, key=valid.source.get("pgp-key", ""))
    if not valid.ok:
        # The GraphQL parameter is called key, but we call it pgp-key to
        # disambiguate from SSH keys, which are configured on the same page.
        for err in valid.errors:
            if err.field == "key":
                err.field = "pgp-key"
        return render_template("keys.html", **valid.kwargs), 400
    return redirect("/keys")

@keys.route("/keys/delete-pgp/<int:key_id>", methods=["POST"])
@loginrequired
def pgp_keys_delete(key_id):
    # TODO: Move this logic into GQL
    if key_id == current_user.pgp_key_id:
        return render_template("keys.html",
                current_user=user, tried_to_delete_key_in_use=True), 400
    resp = exec_gql("meta.sr.ht", """
    mutation DeletePGPKey($key: Int!) {
        deletePGPKey(id: $key) { id }
    }
    """, key=key_id)
    return redirect("/keys")
