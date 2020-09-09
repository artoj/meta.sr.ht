from flask import Blueprint, render_template
from srht.oauth import loginrequired

oauth2 = Blueprint('oauth2', __name__)

@oauth2.route("/oauth2")
@loginrequired
def oauth2_dashboard():
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
