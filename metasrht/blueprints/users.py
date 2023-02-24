import socket
from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, redirect, url_for, abort
from flask import session
from metasrht.decorators import adminrequired
from metasrht.email import send_email
from metasrht.types import Invoice
from metasrht.types import User, UserAuthFactor, FactorType, AuditLogEntry
from metasrht.types import UserNote, PaymentInterval
from metasrht.audit import audit_log
from metasrht.webhooks import UserWebhook, deliver_profile_update
from sqlalchemy import and_
from srht.config import cfg
from srht.database import db
from srht.flask import paginate_query
from srht.graphql import exec_gql, gql_time
from srht.oauth import UserType, login_user, current_user
from srht.search import search_by
from srht.validation import Validation
from string import Template

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

def render_user_template(user, **kwargs):
    totp = (UserAuthFactor.query
        .filter(UserAuthFactor.user_id == user.id)
        .filter(UserAuthFactor.factor_type == FactorType.totp)).one_or_none()
    audit_log = (AuditLogEntry.query
        .filter(AuditLogEntry.user_id == user.id)
        .order_by(AuditLogEntry.created.desc())).limit(15)
    invoices = (Invoice.query
        .filter(Invoice.user_id == user.id)
        .order_by(Invoice.created.desc())).all()
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
        r = exec_gql("meta.sr.ht", dashboard_query, user=user)
        personal_tokens = r["personalAccessTokens"]
        for pt in personal_tokens:
            pt["issued"] = gql_time(pt["issued"])
            pt["expires"] = gql_time(pt["expires"])
        oauth_clients = r["oauthClients"]
        oauth_grants = r["oauthGrants"]
        for grant in oauth_grants:
            grant["issued"] = gql_time(grant["issued"])
            grant["expires"] = gql_time(grant["expires"])
    except:
        personal_tokens = []
        oauth_clients = []
        oauth_grants = []
    return render_template("user.html", user=user,
            totp=totp, audit_log=audit_log, reset_pending=reset_pending,
            one_year=one_year, rdns=rdns,
            personal_tokens=personal_tokens,
            oauth_clients=oauth_clients,
            oauth_grants=oauth_grants,
            invoices=invoices,
            **kwargs)

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

@users.route("/users/~<username>/transfer-billing", methods=["POST"])
@adminrequired
def user_transfer_billing(username):
    user = User.query.filter(User.username == username).one_or_none()
    if not user:
        abort(404)
    valid = Validation(request)
    target = valid.require("target")
    if not valid.ok:
        return render_user_template(user, **valid.kwargs)
    target = User.query.filter(User.username == target).one_or_none()
    valid.expect(target, "User not found", field="target")
    if not valid.ok:
        return render_user_template(user, **valid.kwargs)

    invoice = Invoice()
    invoice.cents = 0
    invoice.user_id = target.id
    invoice.valid_thru = user.payment_due
    invoice.source = f"Billing transfer from ~{user.username}"
    db.session.add(invoice)

    target.payment_cents = user.payment_cents
    target.payment_due = user.payment_due
    target.payment_interval = user.payment_interval
    target.stripe_customer = user.stripe_customer
    target.user_type = UserType.active_paying

    user.stripe_customer = None
    user.payment_due = None
    user.payment_cents = 0
    user.user_type = UserType.active_non_paying

    note = UserNote()
    note.user_id = user.id
    note.note = f"Billing information transferred to ~{target.username}"
    db.session.add(note)

    note = UserNote()
    note.user_id = target.id
    note.note = f"Billing information transferred from ~{user.username}"
    db.session.add(note)

    db.session.commit()
    deliver_profile_update(user)
    deliver_profile_update(target)
    return redirect(url_for(".user_by_username_GET", username=target.username))

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

    deliver_profile_update(user)
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
    deliver_profile_update(user)
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

    user.user_type = UserType.active_paying

    db.session.commit()
    deliver_profile_update(user)
    return redirect(url_for(".user_by_username_GET", username=username))

@users.route("/users/~<username>/impersonate", methods=["POST"])
@adminrequired
def user_impersonate_POST(username):
    user = User.query.filter(User.username == username).one_or_none()
    if not user:
        abort(404)
    valid = Validation(request)
    reason = valid.require("reason", friendly_name="Reason")
    if not valid.ok:
        return redirect(url_for(".user_by_username_GET", username=username))

    details = f"admin log-in from {current_user.canonical_name}: {reason}"
    audit_log(details, details=details, user=user, email=True,
            subject="A sourcehut administrator has logged into your account",
            email_details=details)

    security_addr = cfg("sr.ht", "security-address", default=None)
    if security_addr is not None:
        tmpl = Template("""Subject: A sourcehut admin has impersonated another user

Administrator $admin_user has impersonated $target_user for the following reason:

$reason""")
        rendered = tmpl.substitute(**{
                'admin_user': current_user.canonical_name,
                'target_user': user.canonical_name,
                'reason': reason,
            })
        send_email(security_addr, rendered)

    note = UserNote()
    note.user_id = user.id
    note.note = f"Admin {current_user.canonical_name} impersonated this user: {reason}"
    db.session.add(note)
    db.session.commit()

    login_user(user, set_cookie=True)
    return redirect("/")

@users.route("/users/~<username>/delete", methods=["POST"])
@adminrequired
def user_delete_POST(username):
    if request.form.get("safe-1") != "on":
        return redirect(url_for(".user_by_username_GET", username=username))
    if request.form.get("safe-2") != "on":
        return redirect(url_for(".user_by_username_GET", username=username))

    user = User.query.filter(User.username == username).one_or_none()
    r = exec_gql("meta.sr.ht", """
    mutation {
        deleteUser(reserve: false)
    }
    """, user=user)

    session["notice"] = "This user account is being deleted."
    return redirect("/")
