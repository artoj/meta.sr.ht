import requests
from datetime import datetime
from flask import Blueprint, render_template, redirect, request, session
from flask import url_for
from srht.crypto import encrypt_request_authorization
from srht.config import config, get_origin
from srht.flask import DATE_FORMAT 
from srht.oauth import current_user, loginrequired
from srht.validation import Validation

oauth2 = Blueprint('oauth2', __name__)

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

def validate_grants(literal, valid, field="literal_grants"):
    grants = literal.split(",")
    for grant in grants:
        valid.expect("/" in grant,
                f"Invalid grant {grant}; expected service/scope:access",
                field=field)
        if not valid.ok:
            continue
        svc, scope = grant.split("/")
        if ":" in scope:
            scope, access = scope.split(":")
        else:
            access = "RO"
        valid.expect(access in ["RO", "RW"],
                f"Invalid grant access level '{access}'", field=field)
        valid.expect(svc in service_scopes,
                f"Invalid grant service '{svc}'", field=field)
        if not valid.ok:
            continue
        valid.expect(scope in service_scopes[svc],
                f"Invalid scope '{scope}' for service {svc}", field=field)
    return grants

def execgql(site, query, **variables):
    return requests.post(f"{get_origin(site)}/query",
            headers=encrypt_request_authorization(current_user),
            json={
                "query": query,
                "variables": variables,
            })

@oauth2.route("/oauth2")
@loginrequired
def dashboard():
    dashboard_query = """
    query {
        oauthGrants {
            id
            client { id, name }
            issued
            expires
        }
        personalAccessTokens { id, issued, expires }
        oauthClients { id, uuid, name }
    }
    """
    # TODO: Run that query
    return render_template("oauth2-dashboard.html")

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
        literal = ",".join(grants)
    elif literal:
        grants = validate_grants(literal, valid)

    if not valid.ok:
        return render_template("oauth2-personal-token-registration.html",
                access_grants=access_grants, grants=grants, **valid.kwargs)

    issue_token = """
    mutation IssueToken($grants: [AccessGrantInput], $comment: String) {
        issuePersonalAccessToken(grants: $grants, comment: $comment) {
            secret
            token { expires }
        }
    }
    """

    assert len(grants) == 0 # TODO: Prepare grants properly
    r = execgql("meta.sr.ht", issue_token, grants=None, comment=comment)
    j = r.json()
    if r.status_code != 200:
        for err in j["errors"]:
            valid.error("Internal error: " + err["message"])
        return render_template("oauth2-personal-token-registration.html",
                access_grants=access_grants, grants=grants, **valid.kwargs)
    registration = j["data"]["issuePersonalAccessToken"]
    session["registration"] = registration
    return redirect(url_for("oauth2.personal_token_issued_GET"))

@oauth2.route("/oauth2/personal-token/issued")
@loginrequired
def personal_token_issued_GET():
    registration = session.pop("registration", None)
    if not registration:
        return redirect(url_for("oauth2.dashboard"))
    expiry = datetime.strptime(
            registration["token"]["expires"],
            "%Y-%m-%dT%H:%M:%SZ")
    secret = registration["secret"]
    return render_template("oauth2-personal-token-issued.html",
            expiry=expiry, secret=secret)
