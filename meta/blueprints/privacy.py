from flask import Blueprint, render_template
from meta.common import loginrequired

privacy = Blueprint('privacy', __name__, template_folder='../../templates')

@privacy.route("/privacy")
@loginrequired
def privacy_GET():
    return render_template("privacy.html")
