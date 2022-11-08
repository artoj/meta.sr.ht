from flask import Blueprint, Response, render_template, request, abort
from flask import redirect, url_for
from metasrht.types import User, UserAuthFactor, FactorType
from srht.config import cfg
from srht.flask import session
from srht.database import db
from srht.oauth import current_user, loginrequired, login_user, logout_user
from srht.graphql import exec_gql
from srht.validation import Validation

profile = Blueprint('profile', __name__)

site_name = cfg("sr.ht", "site-name")

@profile.route("/~<username>.keys")
def user_keys_GET(username):
    user = User.query.filter(User.username == username).one_or_none()
    if not user:
        abort(404)
    resp = Response("\n".join(k.key.strip() for k in user.ssh_keys) + "\n")
    resp.headers["Content-Type"] = "text/plain"
    return resp

@profile.route("/~<username>.pgp")
def user_pgp_keys_GET(username):
    user = User.query.filter(User.username == username).one_or_none()
    if not user:
        abort(404)
    resp = Response("\n".join(k.key.strip() for k in user.pgp_keys) + "\n")
    resp.headers["Content-Type"] = "text/plain"
    return resp

@profile.route("/profile")
@loginrequired
def profile_GET():
    notice = session.pop("notice", None)
    return render_template("profile.html", notice=notice)

@profile.route("/profile", methods=["POST"])
@loginrequired
def profile_POST():
    valid = Validation(request)
    valid.require("email", friendly_name="Email")
    if not valid.ok:
        return render_template("profile.html", **valid.kwargs), 400
    rewrite = lambda value: None if value == "" else value
    input = {
        key: rewrite(valid.source[key]) for key in [
            "email", "url", "location", "bio",
        ] if valid.source.get(key) is not None
    }
    resp = exec_gql("meta.sr.ht", """
        mutation UpdateProfile($input: UserInput!) {
            updateUser(input: $input) { id, email }
        }
    """, valid=valid, input=input)
    if not valid.ok:
        return render_template("profile.html", **valid.kwargs), 400
    if "email" in valid.source and valid.source["email"] != resp["updateUser"]["email"]:
        session["notice"] = "An email has been sent to your new address. Check your inbox to complete the change."
    user = User.query.filter(User.id == resp["updateUser"]["id"]).one()
    login_user(user, set_cookie=True)
    return redirect(url_for(".profile_GET"))

@profile.route("/profile/delete")
@loginrequired
def profile_delete_GET():
    print(session.get("session_login"))
    if not session.get("session_login"):
        logout_user()
        session["login_context"] = "You must re-authenticate before deleting your account."
        return redirect(url_for("auth.login_GET",
                return_to=url_for("profile.profile_delete_POST")))
    return render_template("profile-delete.html")

@profile.route("/profile/delete", methods=["POST"])
@loginrequired
def profile_delete_POST():
    if not session.get("session_login"):
        logout_user()
        session["login_context"] = "You must re-authenticate before deleting your account."
        return redirect(url_for("auth.login_GET",
                return_to=url_for("profile.profile_delete_POST")))
    valid = Validation(request)
    confirm = valid.require("confirm")
    valid.expect(confirm == "on", "You must confirm you really want to delete this account.")
    reserve = valid.optional("reserve-username")
    reserve = reserve == "on"
    if not valid.ok:
        return render_template("profile-delete.html", **valid.kwargs)

    r = exec_gql("meta.sr.ht", """
    mutation DeleteUser($reserve: Boolean!) {
        deleteUser(reserve: $reserve)
    }
    """, reserve=reserve)

    logout_user()
    return redirect(url_for(".profile_deleted_GET"))

@profile.route("/profile/deleted")
def profile_deleted_GET():
    return render_template("profile-deleted.html")
