from flask import Blueprint, render_template, request
from flask_login import current_user
from meta.common import loginrequired
from meta.types import User, EventType, UserAuthFactor, FactorType
from meta.validation import Validation, valid_url
from meta.email import send_email
from meta.config import _cfg
from meta.audit import audit_log
from meta.db import db

profile = Blueprint('profile', __name__, template_folder='../../templates')

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
    url = valid.optional("url", user.url)
    location = valid.optional("location", user.location)
    bio = valid.optional("bio", user.bio)

    valid.expect(not url or 0 <= len(url) <= 256,
            "URL must fewer than 256 characters.", "url")
    valid.expect(not url or valid_url(url),
            "URL must be a valid http or https URL", "url")
    valid.expect(not location or 0 <= len(location) <= 256,
            "Location must fewer than 256 characters.", "location")
    valid.expect(not bio or 0 <= len(bio) <= 4096,
            "Bio must fewer than 4096 characters.", "bio")

    if not valid.ok:
        return render_template("profile.html",
            email=email, url=url, location=location, bio=bio,
            valid=valid), 400

    user.url = url
    user.location = location
    user.bio = bio

    new_email = user.email != email
    if new_email:
        user.new_email = email
        user.gen_confirmation_hash()
        send_email('update_email_old', user.email,
            'Your {} email address is changing'.format(
                _cfg("sr.ht", "site-name")),
            new_email=email)
        send_email('update_email_new', user.new_email,
            'Confirm your {} email address change'.format(
                _cfg("sr.ht", "site-name")),
            new_email=email)

    audit_log(EventType.updated_profile)
    db.commit()

    return render_template("profile.html", new_email=new_email)
