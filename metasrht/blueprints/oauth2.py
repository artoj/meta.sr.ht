import base64
import json
import requests
import urllib
from datetime import datetime
from flask import Blueprint, render_template, redirect, request, session
from flask import url_for
from srht.config import config, cfg, get_origin
from srht.crypto import encrypt_request_authorization
from srht.flask import csrf_bypass
from srht.graphql import exec_gql, gql_time, GraphQLError
from srht.oauth import current_user, loginrequired
from srht.validation import Validation, valid_url

oauth2 = Blueprint('oauth2', __name__)

print("Discovering APIs...")
access_grants = []
service_scopes = {}
for s in config:
    if not s.endswith(".sr.ht"):
        continue
    origin = cfg(s, "api-origin", default=get_origin(s))
    try:
        r = requests.get(f"{origin}/query/api-meta.json", timeout=5)
        if r.status_code != 200:
            continue
    except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout):
        continue
    try:
        scopes = r.json()["scopes"]
    except json.decoder.JSONDecodeError:
        print(f"  Skipping {s}: invalid JSON response")
        continue
    print(f"  Found {s}")
    access_grants.append({
        "name": s,
        "scopes": scopes,
    })
    service_scopes[s] = scopes
print(f"Discovered {len(access_grants)} APIs")

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
        try:
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
        except ValueError:
            valid.error("Invalid grant string. The expected format is a list of space-separated grants in the form &lt;service&gt;/&lt;permission&gt;:&lt;RO|RW&gt;", field=field)
            continue
    return grants

@oauth2.route("/oauth2")
@loginrequired
def dashboard():
    dashboard_query = """
    query {
        personalAccessTokens { id, comment, issued, expires }
        oauthClients { id, uuid, name, url }
        oauthGrants {
            id
            issued
            expires
            tokenHash
            client {
                name
                url
                owner {
                    canonicalName
                }
            }
        }
    }
    """
    r = exec_gql("meta.sr.ht", dashboard_query)
    personal_tokens = r["personalAccessTokens"]
    for pt in personal_tokens:
        pt["issued"] = gql_time(pt["issued"])
        pt["expires"] = gql_time(pt["expires"])
    oauth_clients = r["oauthClients"]
    client_revoked = session.pop("client_revoked", False)
    oauth_grants = r["oauthGrants"]
    for grant in oauth_grants:
        grant["issued"] = gql_time(grant["issued"])
        grant["expires"] = gql_time(grant["expires"])
    return render_template("oauth2-dashboard.html",
            personal_tokens=personal_tokens,
            oauth_clients=oauth_clients,
            client_revoked=client_revoked,
            oauth_grants=oauth_grants)

@oauth2.route("/oauth2/personal-token")
@loginrequired
def personal_token_GET():
    return render_template("oauth2-personal-token-registration.html",
            access_grants=access_grants,
            fixed_literal_grants=request.args.get("grants"))

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
        kwargs = valid.kwargs
        kwargs["grants"] = grants
        return render_template("oauth2-personal-token-registration.html",
                access_grants=access_grants,
                fixed_literal_grants=request.args.get("grants"),
                **valid.kwargs)

    issue_token = """
    mutation IssueToken($grants: String, $comment: String) {
        issuePersonalAccessToken(grants: $grants, comment: $comment) {
            secret
            token { expires }
        }
    }
    """

    r = exec_gql("meta.sr.ht", issue_token, grants=literal, comment=comment)
    registration = r["issuePersonalAccessToken"]
    session["registration"] = registration
    return redirect(url_for("oauth2.personal_token_issued_GET"))

@oauth2.route("/oauth2/personal-token/issued")
@loginrequired
def personal_token_issued_GET():
    registration = session.pop("registration", None)
    if not registration:
        return redirect(url_for("oauth2.dashboard"))
    expiry = gql_time(registration["token"]["expires"])
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
    r = exec_gql("meta.sr.ht", register_client, redirect_uri=redirect_uri,
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
    client_reissued = session.pop("client_reissued", False)
    if not client_uuid or not client_secret:
        return redirect(url_for("oauth2.dashboard"))
    return render_template("oauth2-client-registered.html",
            client_uuid=client_uuid, client_secret=client_secret,
            client_reissued=client_reissued)

@oauth2.route("/oauth2/revoke-personal/<int:token_id>")
@loginrequired
def personal_token_revoke_GET(token_id):
    return render_template("are-you-sure.html",
            blurb="revoke this personal access token",
            action=url_for("oauth2.personal_token_revoke_POST", token_id=token_id),
            cancel=url_for("oauth2.dashboard"))

@oauth2.route("/oauth2/revoke-personal/<int:token_id>", methods=["POST"])
@loginrequired
def personal_token_revoke_POST(token_id):
    revoke_token = """
    mutation RevokeToken($token_id: Int!) {
        revokePersonalAccessToken(id: $token_id) { id }
    }
    """
    exec_gql("meta.sr.ht", revoke_token, token_id=token_id)
    return redirect(url_for("oauth2.dashboard"))

@oauth2.route("/oauth2/revoke-bearer/<token_hash>")
@loginrequired
def bearer_token_revoke_GET(token_hash):
    return render_template("are-you-sure.html",
            blurb="revoke this access token",
            action=url_for("oauth2.bearer_token_revoke_POST",
                token_hash=token_hash),
            cancel=url_for("oauth2.dashboard"))

@oauth2.route("/oauth2/revoke-bearer/<token_hash>", methods=["POST"])
@loginrequired
def bearer_token_revoke_POST(token_hash):
    revoke_token = """
    mutation RevokeToken($token_hash: String!) {
        revokeOAuthGrant(hash: $token_hash) { id }
    }
    """
    exec_gql("meta.sr.ht", revoke_token, token_hash=token_hash)
    return redirect(url_for("oauth2.dashboard"))

@oauth2.route("/oauth2/client-registration/<uuid>")
@loginrequired
def manage_client_GET(uuid):
    query = """
    query GetOAuthClient($uuid: String!) {
        oauthClientByUUID(uuid: $uuid) {
            description
            name
            redirectUrl
            url
            uuid
        }
    }
    """
    r = exec_gql("meta.sr.ht", query, uuid=uuid)
    return render_template("oauth2-manage-client.html",
            client=r["oauthClientByUUID"])

@oauth2.route("/oauth2/client-registration/<uuid>/reissue", methods=["POST"])
@loginrequired
def reissue_client_secrets_POST(uuid):
    query = """
    query GetOAuthClient($uuid: String!) {
        oauthClientByUUID(uuid: $uuid) {
            id
            description
            name
            redirectUrl
            url
        }
    }
    """
    r = exec_gql("meta.sr.ht", query, uuid=uuid)
    redirect_uri = r["oauthClientByUUID"]["redirectUrl"]
    client_name = r["oauthClientByUUID"]["name"]
    client_description = r["oauthClientByUUID"]["description"]
    client_url = r["oauthClientByUUID"]["url"]

    query = """
    mutation ReissueOAuthClient($uuid: String!,
            $redirect_uri: String!, $client_name: String!,
            $client_description: String, $client_url: String) {
        revokeOAuthClient(uuid: $uuid) { id }

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
    r = exec_gql("meta.sr.ht", query, uuid=uuid,
            redirect_uri=redirect_uri, client_name=client_name,
            client_description=client_description, client_url=client_url)
    session["client_reissued"] = True
    session["client_uuid"] = r["registerOAuthClient"]["client"]["uuid"]
    session["client_secret"] = r["registerOAuthClient"]["secret"]
    return redirect(url_for("oauth2.client_registration_complete_GET"))

@oauth2.route("/oauth2/client-registration/<uuid>/unregister", methods=["POST"])
@loginrequired
def unregister_client_POST(uuid):
    query = """
    mutation UnregisterOAuthClient($uuid: String!) {
        revokeOAuthClient(uuid: $uuid) { id }
    }
    """
    r = exec_gql("meta.sr.ht", query, uuid=uuid)
    session["client_revoked"] = True
    return redirect(url_for("oauth2.client_registration_complete_GET"))

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
    r = exec_gql("meta.sr.ht", lookup_client, uuid=client_id)
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
    if not client:
        return _authorize_error(None, state, "invalid_request", "Invalid client ID")
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
    r = exec_gql("meta.sr.ht", issue_authorization_code, client_uuid=client_id,
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
    if grant_type != "authorization_code":
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
    try:
        r = exec_gql("meta.sr.ht", issue_grant, client_id=client_id,
                authorization=code, client_secret=client_secret)
    except GraphQLError as gqle:
        return gqle.body, 400
    r = r.get("issueOAuthGrant")
    if not r:
        return access_token_error("invalid_grant", "The access grant was denied.")
    expires = gql_time(r["grant"]["expires"])
    return {
        "access_token": r["secret"],
        "token_type": "bearer",
        "expires_in": int((expires - datetime.utcnow()).seconds),
        "scope": r["grants"],
    }

# Sends the OAuth 2 server metadata as specified by RFC 8414.
@oauth2.route("/.well-known/oauth-authorization-server")
@csrf_bypass
def server_metadata_GET():
    origin = get_origin("meta.sr.ht", external=True)
    scopes = []
    for service in access_grants:
        svc = service["name"]
        for scope in service["scopes"]:
            for access in ["RO", "RW"]:
                scopes.append(f"{svc}/{scope}:{access}")
    return {
        "issuer": origin,
        "authorization_endpoint": origin + "/oauth2/authorize",
        "token_endpoint": origin + "/oauth2/access-token",
        "scopes_supported": scopes,
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "service_documentation": "https://man.sr.ht/meta.sr.ht/oauth.md",
    }
