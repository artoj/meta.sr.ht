import base64
import requests
import urllib
from datetime import datetime
from flask import Blueprint, render_template, redirect, request, session
from flask import url_for
from srht.config import config, get_origin
from srht.crypto import encrypt_request_authorization
from srht.flask import csrf_bypass
from srht.oauth import current_user, loginrequired
from srht.validation import Validation, valid_url

oauth2 = Blueprint('oauth2', __name__)

# TODO: re-home this constant
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

print("Discovering APIs...")
access_grants = []
service_scopes = {}
for s in config:
    if not s.endswith(".sr.ht"):
        continue
    origin = get_origin(s)
    r = requests.get(f"{origin}/query/api-meta.json")
    if r.status_code != 200:
        continue
    print(f"Found {s}")
    access_grants.append({
        "name": s,
        "scopes": r.json()["scopes"],
    })
    service_scopes[s] = r.json()["scopes"]

def parse_grant(grant):
    svc, scope = grant.split("/")
    if ":" in scope:
        scope, access = scope.split(":")
    else:
        access = "RO"
    return svc, scope, access

def validate_grants(literal, valid, field="literal_grants"):
    grants = []
    for grant in literal.split(" "):
        valid.expect("/" in grant,
                f"Invalid grant {grant}; expected service/scope:access",
                field=field)
        if not valid.ok:
            continue
        svc, scope, access = parse_grant(grant)
        valid.expect(access in ["RO", "RW"],
                f"Invalid grant access level '{access}'", field=field)
        valid.expect(svc in service_scopes,
                f"Invalid grant service '{svc}'", field=field)
        if not valid.ok:
            continue
        valid.expect(scope in service_scopes[svc],
                f"Invalid scope '{scope}' for service {svc}", field=field)
        grants.append((svc, scope, access))
    return grants

def execgql(site, query, user=None, client_id=None, **variables):
    r = requests.post(f"{get_origin(site)}/query",
            headers=encrypt_request_authorization(
                user=user, client_id=client_id),
            json={
                "query": query,
                "variables": variables,
            })
    if r.status_code != 200:
        raise Exception(r.text)
    return r.json()["data"]

@oauth2.route("/oauth2")
@loginrequired
def dashboard():
    dashboard_query = """
    query {
        personalAccessTokens { id, comment, issued, expires }
        oauthClients { id, uuid, name, url }
    }
    """
    r = execgql("meta.sr.ht", dashboard_query)
    personal_tokens = r["personalAccessTokens"]
    for pt in personal_tokens:
        pt["issued"] = datetime.strptime(pt["issued"], DATE_FORMAT)
        pt["expires"] = datetime.strptime(pt["expires"], DATE_FORMAT)
    oauth_clients = r["oauthClients"]
    return render_template("oauth2-dashboard.html",
            personal_tokens=personal_tokens,
            oauth_clients=oauth_clients)

@oauth2.route("/oauth2/personal-token")
@loginrequired
def personal_token_GET():
    return render_template("oauth2-personal-token-registration.html",
            access_grants=access_grants)

@oauth2.route("/oauth2/personal-token", methods=["POST"])
@loginrequired
def personal_token_POST():
    valid = Validation(request)
    comment = valid.optional("comment")
    literal = valid.optional("literal_grants")
    ro = valid.optional("read_only", default="off") == "on"
    valid.expect(not literal or "grants" not in valid.source,
            "Use either the selection box or a grant string; not both",
            field="literal_grants")
    grants = []

    if "grants" in valid.source:
        for grant in request.form.getlist("grants"):
            grants.append(f"{grant}:{'RO' if ro else 'RW'}")
        literal = " ".join(grants)
    elif literal:
        grants = validate_grants(literal, valid)

    if not valid.ok:
        return render_template("oauth2-personal-token-registration.html",
                access_grants=access_grants, grants=grants, **valid.kwargs)

    issue_token = """
    mutation IssueToken($grants: String, $comment: String) {
        issuePersonalAccessToken(grants: $grants, comment: $comment) {
            secret
            token { expires }
        }
    }
    """

    r = execgql("meta.sr.ht", issue_token, grants=literal, comment=comment)
    registration = r["issuePersonalAccessToken"]
    session["registration"] = registration
    return redirect(url_for("oauth2.personal_token_issued_GET"))

@oauth2.route("/oauth2/personal-token/issued")
@loginrequired
def personal_token_issued_GET():
    registration = session.pop("registration", None)
    if not registration:
        return redirect(url_for("oauth2.dashboard"))
    expiry = datetime.strptime(registration["token"]["expires"], DATE_FORMAT)
    secret = registration["secret"]
    return render_template("oauth2-personal-token-issued.html",
            expiry=expiry, secret=secret)

@oauth2.route("/oauth2/client-registration")
@loginrequired
def client_registration_GET():
    return render_template("oauth2-register-client.html")

@oauth2.route("/oauth2/client-registration", methods=["POST"])
@loginrequired
def client_registration_POST():
    valid = Validation(request)
    client_name = valid.require("client_name")
    redirect_uri = valid.require("redirect_uri")
    client_description = valid.optional("client_description")
    client_url = valid.optional("client_url")
    valid.expect(valid_url(redirect_uri), "Invalid URL", field="redirect_uri")
    valid.expect(not client_url or valid_url(client_url),
            "Invalid URL", field="client_url")
    if not valid.ok:
        return render_template("oauth2-register-client.html", **valid.kwargs)

    register_client = """
    mutation RegisterClient($redirect_uri: String!, $client_name: String!,
            $client_description: String, $client_url: String) {
        registerOAuthClient(
                redirectUri: $redirect_uri,
                clientName: $client_name,
                clientDescription: $client_description,
                clientUrl: $client_url) {
            client {
                uuid
            }
            secret
        }
    }
    """
    r = execgql("meta.sr.ht", register_client, redirect_uri=redirect_uri,
            client_name=client_name, client_description=client_description,
            client_url=client_url)
    session["client_uuid"] = r["registerOAuthClient"]["client"]["uuid"]
    session["client_secret"] = r["registerOAuthClient"]["secret"]
    return redirect(url_for("oauth2.client_registration_complete_GET"))

@oauth2.route("/oauth2/client-registered")
@loginrequired
def client_registration_complete_GET():
    client_uuid = session.pop("client_uuid", None)
    client_secret = session.pop("client_secret", None)
    if not client_uuid or not client_secret:
        return redirect(url_for("oauth2.dashboard"))
    return render_template("oauth2-client-registered.html",
            client_uuid=client_uuid, client_secret=client_secret)

@oauth2.route("/oauth2/revoke/<int:token_id>")
@loginrequired
def personal_token_revoke_GET(token_id):
    return render_template("are-you-sure.html",
            blurb="revoke this personal access token",
            action=url_for("oauth2.personal_token_revoke_POST", token_id=token_id),
            cancel=url_for("oauth2.dashboard"))

@oauth2.route("/oauth2/revoke/<int:token_id>", methods=["POST"])
@loginrequired
def personal_token_revoke_POST(token_id):
    revoke_token = """
    mutation RevokeToken($token_id: Int!) {
        revokePersonalAccessToken(id: $token_id) { id }
    }
    """
    execgql("meta.sr.ht", revoke_token, token_id=token_id)
    return redirect(url_for("oauth2.dashboard"))

@oauth2.route("/oauth2/client-registration/<uuid>")
@loginrequired
def manage_client_GET(uuid):
    query = """
    query GetOAuthClient($uuid: String!) {
        oauthClientByUUID(uuid: $uuid) { id, uuid, name, url }
    }
    """
    r = execgql("meta.sr.ht", query, uuid=uuid)
    return render_template("oauth2-manage-client.html",
            client=r["oauthClientByUUID"])

def _oauth2_redirect(redirect_uri, **params):
    parts = list(urllib.parse.urlparse(redirect_uri))
    parsed = urllib.parse.parse_qs(parts[4])
    parsed.update(params)
    parts[4] = urllib.parse.urlencode(parsed)
    return redirect(urllib.parse.urlunparse(parts))

def _authorize_error(redirect_uri, state, error_code, error_description):
    if not redirect_uri:
        return render_template("oauth2-error.html",
                code=error_code, description=error_description)
    return _oauth2_redirect(redirect_uri, error=error_code,
            error_description=error_description,
            error_uri="https://man.sr.ht/meta.sr.ht/oauth.md",
            state=state)

def _lookup_client(client_id):
    lookup_client = """
    query OAuthClient($uuid: String!) {
        oauthClientByUUID(uuid: $uuid) {
            name
            description
            url
            redirectUrl
            owner {
                canonicalName
                ... on User {
                    username
                }
            }
        }
    }
    """
    r = execgql("meta.sr.ht", lookup_client, uuid=client_id)
    return r["oauthClientByUUID"]

@oauth2.route("/oauth2/authorize")
@loginrequired
def authorize_GET():
    response_type = request.args.get("response_type")
    client_id = request.args.get("client_id")
    scope = request.args.get("scope")
    state = request.args.get("state")

    if "redirect_uri" in request.args:
        return _authorize_error(None, state, "invalid_request",
                "The redirect_uri parameter is not supported")
    if not client_id:
        return _authorize_error(None, state, "invalid_request",
                "The client_id parameter is required")

    try:
        client = _lookup_client(client_id)
    except Exception as ex:
        return _authorize_error(None, state, "server_error", str(ex))
    redirect_uri = client["redirectUrl"]

    if response_type != "code":
        return _authorize_error(redirect_uri, state, "unsupported_response_type",
                "The response_type parameter must be set to 'code'")
    if not scope:
        return _authorize_error(redirect_uri, state, "invalid_scope",
                "The scope parameter is required")

    valid = Validation({})
    grants = validate_grants(scope, valid)
    if not valid.ok:
        return _authorize_error(redirect_uri, state, "invalid_scope",
                ", ".join(e.message for e in valid.errors))

    return render_template("oauth2-authorization.html",
            client=client, grants=grants, client_id=client_id,
            redirect_uri=redirect_uri, state=state)

@oauth2.route("/oauth2/authorize", methods=["POST"])
@loginrequired
def authorize_POST():
    valid = Validation(request)
    client_id = valid.require("client_id")
    redirect_uri = valid.require("redirect_uri")
    state = valid.optional("state")

    grants = []
    for grant in request.form:
        if grant in ["accept", "reject", "client_id", "redirect_uri", "state",
                "_csrf_token"]:
            continue
        svc, scope, access = parse_grant(grant)
        grants.append((svc, scope, access))

    final_grants = []
    for grant in grants:
        svc, scope, access = grant
        valid.expect(access != "RW" or (svc, scope, "RO") in grants,
                "Cannot remove read access without also removing write access",
                field=f"{svc}/{scope}:RO")
        if access != "RO" or (svc, scope, "RW") not in grants:
            final_grants.append(grant) # de-dupe RO+RW
    grants = final_grants

    if not valid.ok:
        try:
            client = _lookup_client(client_id)
        except Exception as ex:
            return _authorize_error(None, state, "server_error", str(ex))
        return render_template("oauth2-authorization.html",
                client=client, grants=grants, **valid.kwargs)

    issue_authorization_code = """
    mutation IssueAuthorization($client_uuid: String!, $grants: String!) {
        issueAuthorizationCode(clientUUID: $client_uuid, grants: $grants)
    }
    """
    r = execgql("meta.sr.ht", issue_authorization_code, client_uuid=client_id,
            grants=" ".join(f"{g[0]}/{g[1]}:{g[2]}" for g in grants))
    code = r["issueAuthorizationCode"]

    return _oauth2_redirect(redirect_uri, **{
        "code": code,
        **({ "state": state } if state else {}),
    })

def access_token_error(code, description, status=400):
    return {
        "error": code,
        "error_description": description,
        "error_uri": "https://man.sr.ht/meta.sr.ht/oauth.md",
    }, status

@oauth2.route("/oauth2/access-token", methods=["POST"])
@csrf_bypass
def access_token_POST():
    content_type = request.headers.get("Content-Type")
    if content_type != "application/x-www-form-urlencoded":
        return access_token_error("invalid_request",
                "Content-Type must be application/x-www-form-urlencoded")

    grant_type = request.form.get("grant_type")
    code = request.form.get("code")
    redirect_uri = request.form.get("redirect_uri")
    client_id = request.form.get("client_id")
    client_secret = request.form.get("client_secret")

    auth = request.headers.get("Authorization")
    if auth and (client_id or client_secret):
        return access_token_error("invalid_client",
                "Cannot supply both client_id & client_secret and Authorziation header",
                status=401)
    elif auth:
        parts = auth.split(" ")
        if len(parts) != 2 or parts[0] != "Basic":
            return access_token_error("invalid_client",
                    "Invalid Authorization header", status=401)
        auth = base64.b64decode(parts[1]).decode()
        if not ":" in auth:
            return access_token_error("invalid_client",
                    "Invalid Authorization header", status=401)
        client_id, client_secret = auth.split(":", 1)
    elif not client_id or not client_secret:
        return access_token_error("invalid_client",
                "Missing client authorization", status=401)

    if not grant_type:
        return access_token_error("invalid_request",
                "The grant_type parameter is required")
    if grant_type != "code":
        return access_token_error("unsupported_grant_type",
                f"Unsupported grant type '{grant_type}'")
    if not code:
        return access_token_error("invalid_request",
                "The code parameter is required")
    if redirect_uri:
        return access_token_error("invalid_request",
                "This OAuth implementation does not support a per-authorization redirect_uri")

    issue_grant = """
    mutation IssueGrant($authorization: String!, $client_secret: String!) {
        issueOAuthGrant(authorization: $authorization,
                clientSecret: $client_secret) {
            grant {
                expires
            }
            grants
            secret
        }
    }
    """
    r = execgql("meta.sr.ht", issue_grant, client_id=client_id,
            authorization=code, client_secret=client_secret)
    r = r.get("issueOAuthGrant")
    if not r:
        return access_token_error("invalid_grant", "The access grant was denied.")
    expires = datetime.strptime(r["grant"]["expires"], DATE_FORMAT)
    return {
        "access_token": r["secret"],
        "token_type": "bearer",
        "expires_in": str(int((expires - datetime.utcnow()).seconds)),
        "scope": r["grants"],
    }
