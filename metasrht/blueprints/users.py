import socket
from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, redirect, url_for, abort
from metasrht.blueprints.oauth2 import execgql, DATE_FORMAT
from metasrht.decorators import adminrequired
from metasrht.types import Invoice
from metasrht.types import User, UserAuthFactor, FactorType, AuditLogEntry
from metasrht.types import UserNote, PaymentInterval
from metasrht.webhooks import UserWebhook
from sqlalchemy import and_
from srht.database import db
from srht.flask import paginate_query
from srht.oauth import UserType
from srht.search import search_by
from srht.validation import Validation

users = Blueprint("users", __name__)

@users.route("/users")
@adminrequired
def users_GET():
    terms = request.args.get("search")
    users = User.query.order_by(User.created.desc())

    search_error = None
    try:
        users = search_by(users, terms, [User.username, User.email])
    except ValueError as ex:
        search_error = str(ex)

    users, pagination = paginate_query(users)
    return render_template("users.html",
            users=users, search=terms, search_error=search_error, **pagination)

def render_user_template(user):
    totp = (UserAuthFactor.query
        .filter(UserAuthFactor.user_id == user.id)
        .filter(UserAuthFactor.factor_type == FactorType.totp)).one_or_none()
    audit_log = (AuditLogEntry.query
        .filter(AuditLogEntry.user_id == user.id)
        .order_by(AuditLogEntry.created.desc())).limit(15)
    rdns = dict()
    for log in audit_log:
        addr = str(log.ip_address)
        if addr not in rdns:
            try:
                host, _, _ = socket.gethostbyaddr(addr)
                rdns[addr] = host
            except socket.herror:
                continue
    if user.reset_expiry:
        reset_pending = user.reset_expiry > datetime.utcnow()
    else:
        reset_pending = False
    one_year = datetime.utcnow()
    one_year = datetime(year=one_year.year + 1,
            month=one_year.month, day=one_year.day)
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
    try:
        r = execgql("meta.sr.ht", dashboard_query, user=user)
        personal_tokens = r["personalAccessTokens"]
        for pt in personal_tokens:
            pt["issued"] = datetime.strptime(pt["issued"], DATE_FORMAT)
            pt["expires"] = datetime.strptime(pt["expires"], DATE_FORMAT)
        oauth_clients = r["oauthClients"]
        oauth_grants = r["oauthGrants"]
        for grant in oauth_grants:
            grant["issued"] = datetime.strptime(grant["issued"], DATE_FORMAT)
            grant["expires"] = datetime.strptime(grant["expires"], DATE_FORMAT)
    except:
        personal_tokens = []
        oauth_clients = []
        oauth_grants = []
    return render_template("user.html", user=user,
            totp=totp, audit_log=audit_log, reset_pending=reset_pending,
            one_year=one_year, rdns=rdns,
            personal_tokens=personal_tokens,
            oauth_clients=oauth_clients,
            oauth_grants=oauth_grants)

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
        if token.client and token.client.preauthorized:
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
        if token.client and token.client.preauthorized:
            first_party_ids.append(token.id)

    UserWebhook.deliver(UserWebhook.Events.profile_update,
            user.to_dict(first_party=True),
            and_(UserWebhook.Subscription.user_id == user.id,
                UserWebhook.Subscription.token_id in first_party_ids))

    return redirect(url_for(".user_by_username_GET", username=username))

@users.route("/users/~<username>/invoice", methods=["POST"])
@adminrequired
def user_invoice(username):
    user = User.query.filter(User.username == username).one_or_none()
    if not user:
        abort(404)
    valid = Validation(request)
    amount = valid.require("amount")
    amount = int(amount) if amount else 0
    valid_thru = valid.require("valid_thru")
    valid_thru = datetime.strptime(valid_thru, "%Y-%m-%d") if valid_thru else None
    source = valid.require("source")
    if not valid.ok:
        return redirect(url_for(".user_by_username_GET", username=username))

    invoice = Invoice()
    invoice.cents = amount * 100
    invoice.user_id = user.id
    invoice.valid_thru = valid_thru
    invoice.source = source
    db.session.add(invoice)

    user.payment_due = valid_thru
    if valid_thru > datetime.utcnow() + timedelta(days=30):
        user.payment_interval = PaymentInterval.yearly
    else:
        user.payment_interval = PaymentInterval.monthly

    db.session.commit()

    return redirect(url_for(".user_by_username_GET", username=username))
