import requests
import stripe
from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, redirect
from flask import url_for, abort, Response
from metasrht.audit import audit_log
from metasrht.billing import charge_user
from metasrht.types import User, UserType, PaymentInterval, Invoice
from metasrht.webhooks import deliver_profile_update
from sqlalchemy import and_
from srht.config import cfg, get_origin
from srht.crypto import encrypt_request_authorization
from srht.database import db
from srht.flask import session
from srht.oauth import current_user, loginrequired, freshen_user
from srht.validation import Validation

billing = Blueprint('billing', __name__)
onboarding_redirect = cfg("meta.sr.ht::settings", "onboarding-redirect")

@billing.route("/billing")
@loginrequired
def billing_GET():
    message = session.get("message")
    if message:
        del session["message"]
    customer = None
    if current_user.stripe_customer:
        customer = stripe.Customer.retrieve(current_user.stripe_customer)
    total_users = (User.query
            .filter(User.user_type != UserType.unconfirmed)
            .filter(User.user_type != UserType.suspended)).count()
    total_paid = (User.query
            .filter(User.payment_cents != 0)
            .filter(User.user_type == UserType.active_paying)).count()
    invoices = (Invoice.query
            .filter(Invoice.user_id == current_user.id)
            .order_by(Invoice.created.desc())).all()
    return render_template("billing.html", message=message, customer=customer,
            total_users=total_users, total_paid=total_paid,
            paid_pct="{:.2f}".format(total_paid / total_users * 100),
            invoices=invoices)

@billing.route("/billing/initial")
@loginrequired
def billing_initial_GET():
    total_users = (User.query
            .filter(User.user_type != UserType.unconfirmed)
            .filter(User.user_type != UserType.suspended)).count()
    total_paid = (User.query
            .filter(User.payment_cents != 0)
            .filter(User.user_type == UserType.active_paying)).count()
    return_to = request.args.get("return_to")
    if return_to:
        session["return_to"] = return_to
    return render_template("billing-initial.html",
            total_users=total_users, total_paid=total_paid,
            paid_pct="{:.2f}".format(total_paid / total_users * 100))

@billing.route("/billing/initial", methods=["POST"])
@loginrequired
def billing_initial_POST():
    valid = Validation(request)
    amount = valid.require("amount")
    amount = int(amount)
    plan = valid.require("plan")
    valid.expect(not amount or amount > 0, "Expected amount >0")
    if not valid.ok:
        return "Invalid form submission", 400
    current_user.payment_cents = amount
    db.session.commit()
    if current_user.stripe_customer:
        return redirect(url_for("billing.billing_chperiod_GET"))
    return redirect(url_for("billing.new_payment_GET"))

@billing.route("/billing/change-period")
@loginrequired
def billing_chperiod_GET():
    if not current_user.stripe_customer:
        return redirect(url_for("billing.new_payment_GET"))
    return render_template("billing-change-period.html")

@billing.route("/billing/change-period", methods=["POST"])
def billing_chperiod_POST():
    if not current_user.stripe_customer:
        return redirect(url_for("billing.new_payment_GET"))
    valid = Validation(request)
    term = valid.require("term")
    audit_log("billing", "Payment term changed")
    current_user.payment_interval = PaymentInterval(term)
    success, details = charge_user(current_user)
    db.session.commit()
    freshen_user()
    deliver_profile_update(current_user)

    return_to = session.pop("return_to", None)
    if return_to:
        return redirect(return_to)
    session["message"] = "Your subscription has been updated."
    return redirect(url_for("billing.billing_GET"))

@billing.route("/billing/new-payment")
@loginrequired
def new_payment_GET():
    if not current_user.payment_cents:
        return redirect(url_for("billing.billing_initial_GET"))
    return render_template("new-payment.html",
            amount=current_user.payment_cents)

@billing.route("/billing/new-payment", methods=["POST"])
@loginrequired
def new_payment_POST():
    valid = Validation(request)
    term = valid.require("term")
    token = valid.require("stripe-token")
    if not valid.ok:
        return "Invalid form submission", 400
    if not current_user.stripe_customer:
        new_customer = True
        try:
            customer = stripe.Customer.create(
                    description="~" + current_user.username,
                    email=current_user.email,
                    card=token)
            current_user.stripe_customer = customer.id
            current_user.payment_due = datetime.utcnow() + timedelta(minutes=-5)
        except stripe.error.CardError as e:
            details = e.json_body["error"]["message"]
            return render_template("new-payment.html",
                    amount=current_user.payment_cents, error=details)
    else:
        new_customer = False
        if current_user.user_type != UserType.active_paying:
            current_user.payment_due = datetime.utcnow() + timedelta(minutes=-5)
        try:
            customer = stripe.Customer.retrieve(current_user.stripe_customer)
            source = customer.sources.create(source=token)
            customer.default_source = source.stripe_id
            customer.save()
        except stripe.error.CardError as e:
            details = e.json_body["error"]["message"]
            return render_template("new-payment.html",
                    amount=current_user.payment_cents, error=details)
    audit_log("billing", "New payment method handed")
    current_user.payment_interval = PaymentInterval(term)
    success, details = charge_user(current_user)
    if not success:
        return render_template("new-payment.html",
                amount=current_user.payment_cents, error=details)
    db.session.commit()
    freshen_user()
    deliver_profile_update(current_user)

    return_to = session.pop("return_to", None)
    if return_to:
        return redirect(return_to)
    if new_customer:
        return redirect(url_for("billing.billing_complete"))
    session["message"] = "Your payment method was updated."
    return redirect(url_for("billing.billing_GET"))

@billing.route("/billing/remove-source/<source_id>", methods=["POST"])
@loginrequired
def payment_source_remove(source_id):
    try:
        stripe.Customer.delete_source(
                current_user.stripe_customer,
                source_id)
    except stripe.error.StripeError:
        abort(404)
    session["message"] = "Your payment method was removed successfully."
    return redirect(url_for("billing.billing_GET"))

@billing.route("/billing/set-default-source/<source_id>", methods=["POST"])
@loginrequired
def payment_source_make_default(source_id):
    try:
        stripe.Customer.modify(
                current_user.stripe_customer,
                default_source=source_id)
    except stripe.error.StripeError as ex:
        print(ex)
        abort(404)
    session["message"] = "Your payment method was updated successfully."
    return redirect(url_for("billing.billing_GET"))

@billing.route("/billing/complete")
@loginrequired
def billing_complete():
    return render_template("billing-complete.html",
            onboarding_redirect=onboarding_redirect)

@billing.route("/billing/cancel", methods=["POST"])
@loginrequired
def cancel_POST():
    current_user.payment_cents = 0
    db.session.commit()
    freshen_user()
    deliver_profile_update(current_user)
    audit_log("billing", "Plan cancelled (will not renew)")
    return redirect(url_for("billing.billing_GET"))

@billing.route("/billing/invoice/<int:invoice_id>")
@loginrequired
def invoice_GET(invoice_id):
    invoice = Invoice.query.filter(Invoice.id == invoice_id).one_or_none()
    if not invoice:
        abort(404)
    if (invoice.user_id != current_user.id 
            and current_user.user_type != UserType.admin):
        abort(401)
    return render_template("billing-invoice.html", invoice=invoice)

@billing.route("/billing/invoice/<int:invoice_id>", methods=["POST"])
@loginrequired
def invoice_POST(invoice_id):
    origin = cfg("meta.sr.ht", "api-origin", default=get_origin("meta.sr.ht"))
    headers = {
        "X-Forwarded-For": ", ".join(request.access_route),
        **encrypt_request_authorization(user=current_user),
    }
    r = requests.post(f"{origin}/query/invoice/{invoice_id}",
            headers=headers, data=request.form)
    filename = f"invoice_{invoice_id}.pdf"
    headers = [('Content-Disposition', f'attachment; filename="{filename}"')]
    return Response(r.content, mimetype="application/pdf", headers=headers)
