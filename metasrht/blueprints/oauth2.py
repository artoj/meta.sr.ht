import requests
from flask import Blueprint, render_template, request
from srht.config import config, get_origin
from srht.oauth import loginrequired
from srht.validation import Validation

oauth2 = Blueprint('oauth2', __name__)

print("Discovering APIs...")
access_grants = []
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
    validation = Validation(request)
    # TODO
