from flask import Blueprint, render_template, request, redirect, url_for, abort
from srht.database import db
from srht.flask import paginate_query
from srht.oauth import UserType
from srht.search import search
from srht.validation import Validation
from sqlalchemy import and_
from metasrht.decorators import adminrequired
from metasrht.types import User, UserAuthFactor, FactorType, AuditLogEntry
from metasrht.types import UserNote
from metasrht.webhooks import UserWebhook
from datetime import datetime

users = Blueprint("users", __name__)

@users.route("/users")
@adminrequired
def users_GET():
    terms = request.args.get("search")
    users = User.query.order_by(User.created.desc())
    if terms:
        users = search(users, terms, [
            User.username, User.email
        ], dict())
    users, pagination = paginate_query(users)
    return render_template("users.html",
            users=users, search=terms, **pagination)

def render_user_template(user):
    totp = (UserAuthFactor.query
        .filter(UserAuthFactor.user_id == user.id)
        .filter(UserAuthFactor.factor_type == FactorType.totp)).one_or_none()
    audit_log = (AuditLogEntry.query
        .filter(AuditLogEntry.user_id == user.id)
        .order_by(AuditLogEntry.created.desc())).limit(15)
    if user.reset_expiry:
        reset_pending = user.reset_expiry > datetime.utcnow()
    else:
        reset_pending = False
    return render_template("user.html", user=user,
            totp=totp, audit_log=audit_log, reset_pending=reset_pending)

@users.route("/users/~<username>")
@adminrequired
def user_by_username_GET(username):
    user = User.query.filter(User.username == username).one_or_none()
    if not user:
        abort(404)
    return render_user_template(user)

@users.route("/users/~<username>/add-note", methods=["POST"])
@adminrequired
def user_add_note(username):
    user = User.query.filter(User.username == username).one_or_none()
    if not user:
        abort(404)
    valid = Validation(request)
    notes = valid.require("notes")
    if not valid.ok:
        return render_user_template(user)
    note = UserNote()
    note.user_id = user.id
    note.note = notes
    db.session.add(note)
    db.session.commit()
    return redirect(url_for(".user_by_username_GET", username=username))

@users.route("/users/~<username>/disable-totp", methods=["POST"])
@adminrequired
def user_disable_totp(username):
    user = User.query.filter(User.username == username).one_or_none()
    if not user:
        abort(404)
    UserAuthFactor.query.filter(UserAuthFactor.user_id == user.id).delete()
    db.session.commit()
    return redirect(url_for(".user_by_username_GET", username=username))

@users.route("/users/~<username>/set-type", methods=["POST"])
@adminrequired
def set_user_type(username):
    user = User.query.filter(User.username == username).one_or_none()
    if not user:
        abort(404)

    valid = Validation(request)
    user_type = valid.require("user_type", cls=UserType)
    if not valid.ok:
        return redirect(url_for(".user_by_username_GET", username=username))

    user.user_type = user_type
    db.session.commit()

    first_party_ids = []
    for token in user.oauth_tokens:
        if token.client.preauthorized:
            first_party_ids.append(token.id)

    UserWebhook.deliver(UserWebhook.Events.profile_update,
            user.to_dict(first_party=True),
            and_(UserWebhook.Subscription.user_id == user.id,
                UserWebhook.Subscription.token_id in first_party_ids))

    return redirect(url_for(".user_by_username_GET", username=username))

@users.route("/users/~<username>/suspend", methods=["POST"])
@adminrequired
def user_suspend(username):
    user = User.query.filter(User.username == username).one_or_none()
    if not user:
        abort(404)
    valid = Validation(request)
    reason = valid.optional("reason")
    user.user_type = UserType.suspended
    user.suspension_notice = reason
    db.session.commit()

    first_party_ids = []
    for token in user.oauth_tokens:
        if token.client.preauthorized:
            first_party_ids.append(token.id)

    UserWebhook.deliver(UserWebhook.Events.profile_update,
            user.to_dict(first_party=True),
            and_(UserWebhook.Subscription.user_id == user.id,
                UserWebhook.Subscription.token_id in first_party_ids))

    return redirect(url_for(".user_by_username_GET", username=username))
