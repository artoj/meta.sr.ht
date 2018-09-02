from flask import Blueprint, render_template, redirect, session
from flask_login import current_user
from srht.config import cfg
from srht.database import db
from srht.flask import loginrequired
from metasrht.types import Invite, UserType

invites = Blueprint('invites', __name__)

site_name = cfg("sr.ht", "site-name")
site_root = cfg("meta.sr.ht", "origin")

@invites.route("/invites")
@loginrequired
def index():
    return render_template("invite.html")

@invites.route("/invites/gen-invite", methods=["POST"])
@loginrequired
def gen_invite():
    if current_user.invites == 0 and current_user.user_type != UserType.admin:
        abort(401)
    invite = Invite()
    invite.sender_id = current_user.id
    if current_user.invites > 0:
        current_user.invites -= 1
    db.session.add(invite)
    db.session.commit()
    session["invite_link"] = "{}/register/{}".format(
            site_root, invite.invite_hash)
    return redirect("/invites/generated")

@invites.route("/invites/generated")
@loginrequired
def view_invite():
    invite_link = session.get("invite_link")
    if not invite_link:
        return redirect("/invites")
    del session["invite_link"]
    return render_template("invite-link-generated.html", link=invite_link)
