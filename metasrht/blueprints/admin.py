from flask import Blueprint, render_template, redirect
from metasrht.common import adminrequired
from metasrht.types import Invite
from srht.config import cfg
from srht.database import db

admin = Blueprint('admin', __name__)

site_name = cfg("sr.ht", "site-name")
site_root = cfg("server", "protocol") + "://" + cfg("server", "domain")

@admin.route("/admin")
@adminrequired
def index():
    return render_template("admin.html")

@admin.route("/admin/gen-invite", methods=["POST"])
@adminrequired
def gen_invite():
    invite = Invite()
    db.session.add(invite)
    db.session.commit()
    return redirect("/admin/invite-generated/{}".format(invite.invite_hash))

@admin.route("/admin/invite-generated/<invite_hash>")
@adminrequired
def view_invite(invite_hash):
    return render_template("invite-link-generated.html",
            link="{}/register/{}".format(site_root, invite_hash))
