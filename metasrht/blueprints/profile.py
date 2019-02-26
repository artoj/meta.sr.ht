from flask import Blueprint, render_template, request
from flask_login import current_user
from metasrht.types import User, UserAuthFactor, FactorType
from metasrht.email import send_email
from srht.config import cfg
from srht.database import db
from srht.flask import loginrequired
from srht.validation import Validation

profile = Blueprint('profile', __name__)

site_name = cfg("sr.ht", "site-name")

@profile.route("/profile")
@loginrequired
def profile_GET():
    return render_template("profile.html")

@profile.route("/profile", methods=["POST"])
@loginrequired
def profile_POST():
    valid = Validation(request)
    user = User.query.filter(User.id == current_user.id).one()

    email = valid.optional("email", user.email)
    email = email.strip()
    new_email = user.email != email

    user.update(valid)
    if not valid.ok:
        return render_template("profile.html",
            email=email, url=url, location=location, bio=bio,
            valid=valid), 400

    db.session.commit()
    return render_template("profile.html", new_email=new_email)
