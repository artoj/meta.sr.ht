from flask import Blueprint, render_template, request, redirect, session, abort
from flask_login import current_user
from datetime import datetime
from metasrht.types import OAuthClient, OAuthToken, DelegatedScope
from metasrht.audit import audit_log
from srht.database import db
from srht.flask import loginrequired
from srht.validation import Validation, valid_url

oauth_web = Blueprint('oauth_web', __name__)

@oauth_web.route("/oauth")
@loginrequired
def oauth_GET():
    client_authorizations = OAuthToken.query\
            .join(OAuthToken.client)\
            .filter(OAuthClient.preauthorized == False)\
            .filter(OAuthToken.user_id == current_user.id)\
            .filter(OAuthToken.expires > datetime.utcnow())\
            .filter(OAuthToken.client_id != None).all()
    personal_tokens = OAuthToken.query\
            .filter(OAuthToken.user_id == current_user.id)\
            .filter(OAuthToken.expires > datetime.utcnow())\
            .filter(OAuthToken.client_id == None).all()
    def client_tokens(client):
        return OAuthToken.query \
                .filter(OAuthToken.client_id == client.id).count()
    return render_template("oauth.html", client_tokens=client_tokens,
            client_authorizations=client_authorizations,
            personal_tokens=personal_tokens)

@oauth_web.route("/oauth/register")
@loginrequired
def oauth_register_GET():
    return render_template("oauth-register.html")

@oauth_web.route("/oauth/register", methods=["POST"])
@loginrequired
def oauth_register_POST():
    valid = Validation(request)

    client_name = valid.require("client-name")
    redirect_uri = valid.require("redirect-uri")

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
    session["client_event"] = "registered"
    db.session.add(client)
    audit_log("register oauth client",
            "Registered OAuth client {}".format(client.client_id))
    db.session.commit()
    return redirect("/oauth/registered")

@oauth_web.route("/oauth/registered")
@loginrequired
def oauth_registered():
    client_id = session["client_id"]
    client_secret = session["client_secret"]
    client_event = session["client_event"]
    del session["client_id"]
    del session["client_secret"]
    del session["client_event"]
    return render_template("oauth-registered.html",
            client_id=client_id,
            client_secret=client_secret,
            client_event=client_event)

@oauth_web.route("/oauth/client/<client_id>/settings")
@loginrequired
def client_settings_GET(client_id):
    client = OAuthClient.query.filter(OAuthClient.client_id == client_id).first()
    if not client or client.user_id != current_user.id:
        abort(404)
    return render_template("client-settings.html", client=client)

@oauth_web.route("/oauth/client/<client_id>/security")
@loginrequired
def client_security_GET(client_id):
    client = OAuthClient.query.filter(OAuthClient.client_id == client_id).first()
    if not client or client.user_id != current_user.id:
        abort(404)
    return render_template("client-security.html", client=client)

@oauth_web.route("/oauth/reset-secret/<client_id>", methods=["POST"])
@loginrequired
def reset_secret(client_id):
    client = OAuthClient.query.filter(OAuthClient.client_id == client_id).first()
    if not client or client.user_id != current_user.id:
        abort(404)
    secret = client.gen_client_secret()
    session["client_id"] = client.client_id
    session["client_secret"] = secret
    session["client_event"] = "reset-secret"
    audit_log("reset client secret",
            "Reset OAuth client secret for {}".format(client.client_id))
    db.session.commit()
    return redirect("/oauth/registered")

@oauth_web.route("/oauth/revoke-tokens/<client_id>")
@loginrequired
def revoke_tokens_GET(client_id):
    client = OAuthClient.query.filter(OAuthClient.client_id == client_id).first()
    if not client or client.user_id != current_user.id:
        abort(404)
    return render_template("are-you-sure.html",
            blurb="revoke all OAuth tokens for client {}".format(client_id),
            action="/oauth/revoke-tokens/{}".format(client_id),
            cancel="/oauth")

@oauth_web.route("/oauth/revoke-tokens/<client_id>", methods=["POST"])
@loginrequired
def revoke_tokens_POST(client_id):
    client = OAuthClient.query.filter(OAuthClient.client_id == client_id).first()
    if not client or client.user_id != current_user.id:
        abort(404)
    OAuthToken.query.filter(OAuthToken.client_id == client.id).delete()
    audit_log("revoked oauth tokens",
            "Revoked all OAuth tokens for {}".format(client_id))
    db.session.commit()
    return redirect("/oauth")

@oauth_web.route("/oauth/client/<client_id>/delete")
@loginrequired
def client_delete_GET(client_id):
    client = OAuthClient.query.filter(OAuthClient.client_id == client_id).first()
    if not client or client.user_id != current_user.id:
        abort(404)
    return render_template("client-delete.html", client=client)

@oauth_web.route("/oauth/client/<client_id>/delete", methods=["POST"])
@loginrequired
def client_delete_POST(client_id):
    client = OAuthClient.query.filter(OAuthClient.client_id == client_id).first()
    if not client or client.user_id != current_user.id:
        abort(404)
    audit_log("deleted oauth client", "Deleted OAuth client {}".format(client_id))
    db.session.delete(client)
    db.session.commit()
    return redirect("/oauth")

@oauth_web.route("/oauth/revoke-token/<token_id>")
@loginrequired
def revoke_token_GET(token_id):
    token = OAuthToken.query.filter(OAuthToken.id == token_id).first()
    if not token or token.user_id != current_user.id:
        abort(404)
    if token.client:
        return render_template("are-you-sure.html",
                blurb="revoke all access from <strong>{}</strong> to your account".format(
                    token.client.client_name),
                action="/oauth/revoke-token/{}".format(token_id),
                cancel="/oauth")
    else:
        return render_template("are-you-sure.html",
                blurb="revoke peronsal access token <strong>{}...</strong>".format(
                    token.token_partial),
                action="/oauth/revoke-token/{}".format(token_id),
                cancel="/oauth")

@oauth_web.route("/oauth/revoke-token/<token_id>", methods=["POST"])
@loginrequired
def revoke_token_POST(token_id):
    token = OAuthToken.query.filter(OAuthToken.id == token_id).first()
    if not token or token.user_id != current_user.id:
        abort(404)
    if token.client:
        audit_log("revoked oauth token",
                "revoked access from {}".format(token.client.client_name))
    else:
        audit_log("revoked personal access token",
                "revoked {}...".format(token.token_partial))
    token.expires = datetime.utcnow()
    db.session.commit()
    return redirect("/oauth")

@oauth_web.route("/oauth/personal-token")
@loginrequired
def personal_token_GET():
    return render_template("oauth-personal-token.html")

@oauth_web.route("/oauth/personal-token", methods=["POST"])
@loginrequired
def personal_token_POST():
    oauth_token = OAuthToken(current_user, None)
    token = oauth_token.gen_token()
    oauth_token.scopes = "*"
    audit_log("issued oauth token", "issued personal access token {}...".format(
        oauth_token.token_partial))
    db.session.add(oauth_token)
    db.session.commit()
    return render_template("oauth-personal-token.html", token=token)
