from flask import Blueprint, render_template, request, redirect, session, abort
from flask_login import current_user
from datetime import datetime, timedelta
from metasrht.common import loginrequired
from metasrht.types import OAuthClient, OAuthToken, User, DelegatedScope, RevocationUrl
from metasrht.audit import audit_log
from metasrht.oauth import OAuthScope
from metasrht.redis import redis
from srht.validation import Validation, valid_url
from srht.database import db
import re
import os
import json
import hashlib
import binascii
import urllib

oauth = Blueprint('oauth', __name__)

@oauth.route("/oauth")
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

@oauth.route("/oauth/register")
@loginrequired
def oauth_register_GET():
    return render_template("oauth-register.html")

@oauth.route("/oauth/register", methods=["POST"])
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

@oauth.route("/oauth/registered")
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

@oauth.route("/oauth/client/<client_id>/settings")
@loginrequired
def client_settings_GET(client_id):
    client = OAuthClient.query.filter(OAuthClient.client_id == client_id).first()
    if not client or client.user_id != current_user.id:
        abort(404)
    return render_template("client-settings.html", client=client)

@oauth.route("/oauth/client/<client_id>/security")
@loginrequired
def client_security_GET(client_id):
    client = OAuthClient.query.filter(OAuthClient.client_id == client_id).first()
    if not client or client.user_id != current_user.id:
        abort(404)
    return render_template("client-security.html", client=client)

@oauth.route("/oauth/reset-secret/<client_id>", methods=["POST"])
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

@oauth.route("/oauth/revoke-tokens/<client_id>")
@loginrequired
def revoke_tokens_GET(client_id):
    client = OAuthClient.query.filter(OAuthClient.client_id == client_id).first()
    if not client or client.user_id != current_user.id:
        abort(404)
    return render_template("are-you-sure.html",
            blurb="revoke all OAuth tokens for client {}".format(client_id),
            action="/oauth/revoke-tokens/{}".format(client_id),
            cancel="/oauth")

@oauth.route("/oauth/revoke-tokens/<client_id>", methods=["POST"])
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

@oauth.route("/oauth/client/<client_id>/scopes")
@loginrequired
def client_scopes_GET(client_id):
    client = OAuthClient.query.filter(OAuthClient.client_id == client_id).first()
    if not client or client.user_id != current_user.id:
        abort(404)
    return render_template("client-scopes.html", client=client)

@oauth.route("/oauth/client/<client_id>/scopes", methods=["POST"])
@loginrequired
def client_scopes_POST(client_id):
    client = OAuthClient.query.filter(OAuthClient.client_id == client_id).first()
    if not client or client.user_id != current_user.id:
        abort(404)
    valid = Validation(request)
    name = valid.require("scope_name", friendly_name="Name")
    desc = valid.require("scope_desc", friendly_name="Description")
    valid.expect(re.match(r"^[a-z_]+$", name),
            "Lowercase characters and underscores only", field="name")
    writable = valid.optional("writable") == "on"
    if not valid.ok:
        return render_template("client-scopes.html", client=client, **valid.kwargs)
    prior = DelegatedScope.query\
            .filter(DelegatedScope.client_id == client.id) \
            .filter(DelegatedScope.name == name).first()
    valid.expect(not prior, "A scope exists with this name", field="name")
    if not valid.ok:
        return render_template("client-scopes.html", client=client, **valid.kwargs)
    scope = DelegatedScope(client, name, desc)
    scope.write = writable
    db.session.add(scope)
    db.session.commit()
    return redirect("/oauth/client/{}/scopes".format(client.client_id))

@oauth.route("/oauth/client/<client_id>/scopes/<scope_name>", methods=["POST"])
@loginrequired
def client_scopes_DELETE(client_id, scope_name):
    client = OAuthClient.query.filter(OAuthClient.client_id == client_id).first()
    if not client or client.user_id != current_user.id:
        abort(404)
    scope = DelegatedScope.query\
            .filter(DelegatedScope.client_id == client.id) \
            .filter(DelegatedScope.name == scope_name).first()
    if not scope:
        abort(404)
    db.session.delete(scope)
    db.session.commit()
    return redirect("/oauth/client/{}/scopes".format(client_id))

@oauth.route("/oauth/client/<client_id>/delete")
@loginrequired
def client_delete_GET(client_id):
    client = OAuthClient.query.filter(OAuthClient.client_id == client_id).first()
    if not client or client.user_id != current_user.id:
        abort(404)
    return render_template("client-delete.html", client=client)

@oauth.route("/oauth/client/<client_id>/delete", methods=["POST"])
@loginrequired
def client_delete_POST(client_id):
    client = OAuthClient.query.filter(OAuthClient.client_id == client_id).first()
    if not client or client.user_id != current_user.id:
        abort(404)
    audit_log("deleted oauth client", "Deleted OAuth client {}".format(client_id))
    db.session.delete(client)
    db.session.commit()
    return redirect("/oauth")

@oauth.route("/oauth/revoke-token/<token_id>")
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

@oauth.route("/oauth/revoke-token/<token_id>", methods=["POST"])
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

@oauth.route("/oauth/personal-token")
@loginrequired
def personal_token_GET():
    return render_template("oauth-personal-token.html")

@oauth.route("/oauth/personal-token", methods=["POST"])
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

def oauth_redirect(redirect_uri, **params):
    parts = list(urllib.parse.urlparse(redirect_uri))
    parsed = urllib.parse.parse_qs(parts[4])
    parsed.update(params)
    parts[4] = urllib.parse.urlencode(parsed)
    return redirect(urllib.parse.urlunparse(parts))

def oauth_exchange(client, scopes, state, redirect_uri):
    token = hashlib.sha512(os.urandom(8)).hexdigest()[:12]
    scopes = ','.join([str(s) for s in scopes])
    stash = { "user_id": current_user.id, "client_id": client.id, "scopes": scopes }
    redis.set(token, json.dumps(stash), ex=(15 * 60))

    redirect_params = {
        "exchange": token,
        "scopes": scopes,
    }
    if state:
        redirect_params["state"] = state

    return oauth_redirect(redirect_uri, **redirect_params)

@oauth.route("/oauth/authorize")
@loginrequired
def oauth_authorize_GET():
    client_id = request.args.get('client_id')
    scopes = request.args.get('scopes')
    redirect_uri = request.args.get('redirect_uri')
    state = request.args.get('state')
    print(client_id)
    client = OAuthClient.query.filter(OAuthClient.client_id == client_id).first()

    if not client_id or not client:
        return render_template("oauth-error.html", details="Unknown client ID"), 400

    if not redirect_uri:
        redirect_uri = client.redirect_uri

    if not client.redirect_uri.startswith(redirect_uri):
        return oauth_redirect(redirect_uri, error='invalid_redirect',
                details='The URI provided must use be a subpath of your configured redirect URI')

    try:
        scopes = set(OAuthScope(s) for s in scopes.split(','))
        if not OAuthScope('profile:read') in scopes:
            scopes.update([OAuthScope('profile:read')])
    except Exception as ex:
        return oauth_redirect(redirect_uri,
                error='invalid_scope', details=ex.args[0])

    previous = OAuthToken.query\
            .filter(OAuthToken.user_id == current_user.id)\
            .filter(OAuthToken.client_id == client.id)\
            .filter(OAuthToken.expires > datetime.utcnow())\
            .first()

    if client.preauthorized:
        return oauth_exchange(client, scopes, state, redirect_uri)
    if previous:
        pscopes = set(OAuthScope(s) for s in previous.scopes.split(','))
        if pscopes == scopes:
            return oauth_exchange(client, scopes, state, redirect_uri)

    return render_template("oauth-authorize.html",
            client=client, scopes=scopes,
            redirect_uri=redirect_uri, state=state)

@oauth.route("/oauth/authorize", methods=["POST"])
@loginrequired
def oauth_authorize_POST():
    client_id = request.form.get('client_id')
    redirect_uri = request.form.get('redirect_uri')
    state = request.form.get('state')
    client = OAuthClient.query.filter(OAuthClient.client_id == client_id).first()

    if not client_id or not client:
        return render_template("oauth-error.html", details="Unknown client ID"), 400

    if not redirect_uri:
        redirect_uri = client.redirect_uri

    if not client.redirect_uri.startswith(redirect_uri):
        return oauth_redirect(redirect_uri,
                error='invalid_redirect',
                details='The URI provided must use be a subpath of your configured redirect URI')

    if not "accept" in request.form:
        return oauth_redirect(redirect_uri, error='user_declined',
                details='User declined to grant access to your application')

    scopes = set()

    for key in request.form:
        if key in ["client_id", "state", "redirect_uri", "accept"]:
            continue
        value = request.form.get(key)
        if not value:
            continue
        try:
            scope = OAuthScope(key)
            scopes.update([str(scope)])
        except Exception as ex:
            return render_template("oauth-error.html", details=ex.message), 400

    if not OAuthScope('profile:read') in scopes:
        scopes.update([OAuthScope('profile:read')])

    return oauth_exchange(client, scopes, state, redirect_uri)

@oauth.route("/oauth/exchange", methods=["POST"])
def oauth_exchange_POST():
    valid = Validation(request)
    client_id = valid.require('client_id')
    client_secret = valid.require('client_secret')
    exchange = valid.require('exchange')
    if not valid.ok:
        return valid.response

    client = OAuthClient.query.filter(OAuthClient.client_id == client_id).first()
    valid.expect(client, 'Unknown client ID')
    if not valid.ok:
        return valid.response

    client_secret_hash = hashlib.sha512(client_secret.encode()).hexdigest()
    valid.expect(client_secret_hash == client.client_secret_hash,
            'Invalid client secret')
    if not valid.ok:
        return valid.response

    stash = redis.get(exchange)
    valid.expect(stash, 'Exchange token expired')
    if not valid.ok:
        return valid.response

    stash = json.loads(stash.decode())
    redis.delete(exchange)

    user = stash.get('user_id')
    scopes = stash.get('scopes')
    user = User.query.filter(User.id == user).first()
    valid.expect(user, 'Uh, this is awkward - unknown user ID stored for this exchange token')
    if not valid.ok:
        return valid.response

    previous = OAuthToken.query\
            .filter(OAuthToken.user_id == user.id)\
            .filter(OAuthToken.client_id == client.id)\
            .first()
    if not previous:
        oauth_token = OAuthToken(user, client)
    else:
        oauth_token = previous
    oauth_token.scopes = scopes
    token = oauth_token.gen_token()
    audit_log("oauth token issued",
            "issued oauth token {} to client {}".format(
                oauth_token.token_partial, client.client_id), user=user)
    if not previous:
        db.session.add(oauth_token)
    db.session.commit()

    return {
        "token": token,
        "expires": oauth_token.expires
    }

@oauth.route("/oauth/token/<token>", methods=["POST"])
def oauth_token_POST(token):
    valid = Validation(request)
    client_id = valid.require("client_id")
    client_secret = valid.require("client_secret")
    revocation_url = valid.require("revocation_url")
    if not valid.ok:
        return valid.response
    client = OAuthClient.query.filter(OAuthClient.client_id == client_id).first()
    if not client:
        return { "errors": [ { "reason": "404 not found" } ] }, 404
    client_secret_hash = hashlib.sha512(client_secret.encode()).hexdigest()
    valid.expect(client_secret_hash == client.client_secret_hash,
            "Invalid client secret")
    if not valid.ok:
        return valid.response
    h = hashlib.sha512(token.encode()).hexdigest()
    oauth_token = OAuthToken.query.filter(OAuthToken.token_hash == h).first()
    if not oauth_token:
        return { "errors": [ { "reason": "Invalid or expired OAuth token" } ] }, 400
    if oauth_token.expires < datetime.utcnow():
        return { "errors": [ { "reason": "Invalid or expired OAuth token" } ] }, 400
    if oauth_token.scopes == "*":
        return { "expires": oauth_token.expires, "scopes": "*" }
    scopes = [OAuthScope(s) for s in oauth_token.scopes.split(',')]
    scopes = [
        str(s) for s in scopes
        if (s.client_id and s.client_id == client.client_id)
            or s == OAuthScope("profile:read")
    ]
    if not any(scopes):
        return { "errors": [ { "reason": "Invalid or expired OAuth token" } ] }, 400
    scopes = ",".join(scopes)
    # TODO: Celery task to notify of revocation
    rev = RevocationUrl.query\
            .filter(RevocationUrl.token_id == oauth_token.id)\
            .filter(RevocationUrl.client_id == client.id).first()
    if not rev:
        rev = RevocationUrl(client, oauth_token, revocation_url)
        db.session.add(rev)
    else:
        rev.url = revocation_url
    db.session.commit()
    return {
        "expires": oauth_token.expires,
        "scopes": oauth_token.scopes
    }
