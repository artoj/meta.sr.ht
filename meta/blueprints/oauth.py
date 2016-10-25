from flask import Blueprint, render_template, request, redirect, session
from flask_login import current_user
from meta.validation import Validation, valid_url
from meta.common import loginrequired
from meta.types import OAuthClient, OAuthToken
from meta.audit import audit_log
from meta.db import db

oauth = Blueprint('oauth', __name__, template_folder='../../templates')

@oauth.route("/oauth")
@loginrequired
def oauth_GET():
    def tokens(client):
        return OAuthToken.query \
                .filter(OAuthToken.client_id == client.id).count()
    return render_template("oauth.html", tokens=tokens)

@oauth.route("/oauth/register")
@loginrequired
def oauth_register_GET():
    return render_template("oauth-register.html")

@oauth.route("/oauth/register", methods=["POST"])
@loginrequired
def oauth_register_POST():
    valid = Validation(request)

    client_name = valid.require("client-name")
    redirect_uri = valid.optional("redirect-uri")

    valid.expect(not redirect_uri or valid_url(redirect_uri),
            "Must be a valid HTTP or HTTPS URI", field="redirect-uri")

    if not valid.ok:
        return render_template("oauth-register.html",
                client_name=client_name,
                redirect_uri=redirect_uri,
                valid=valid)

    client = OAuthClient(current_user, client_name, redirect_uri)
    secret = client.gen_client_secret()
    session["client_id"] = client.client_id
    session["client_secret"] = secret
    db.add(client)
    audit_log("register oauth client",
            "Registered OAuth client {}".format(client.client_id))
    db.commit()
    return redirect("/oauth/registered")

@oauth.route("/oauth/registered")
@loginrequired
def oauth_registered():
    client_id = session["client_id"]
    client_secret = session["client_secret"]
    del session["client_id"]
    del session["client_secret"]
    return render_template("oauth-registered.html",
            client_id=client_id, client_secret=client_secret)
