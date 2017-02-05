from flask import Blueprint
from meta.validation import Validation
from meta.audit import audit_log
from meta.oauth import oauth

api = Blueprint('api', __name__)

@api.route("/api/user/profile")
@oauth("profile:read")
def user_profile_GET(token):
    user = token.user
    return {
        "username": user.username,
        "email": user.email,
        "url": user.url,
        "location": user.location,
        "bio": user.bio,
    }
