from flask import Blueprint, render_template
from meta.common import loginrequired

oauth = Blueprint('oauth', __name__, template_folder='../../templates')

@oauth.route("/oauth")
@loginrequired
def oauth_GET():
    return render_template("oauth.html")
