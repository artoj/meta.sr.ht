import stripe
from flask import Blueprint, render_template, request, session, redirect
from flask import url_for
from flask_login import current_user
from srht.database import db
from srht.config import cfg
from srht.flask import loginrequired
from srht.validation import Validation
from metasrht.billing import charge_user
from metasrht.types import User, UserType, PaymentInterval
from datetime import datetime, timedelta

billing = Blueprint('billing', __name__)
onboarding_redirect = cfg("meta.sr.ht::settings", "onboarding-redirect")

@billing.route("/billing")
@loginrequired
def billing_GET():
    message = session.get("message")
    if message:
        del session["message"]
    return render_template("billing.html", message=message)

@billing.route("/billing/initial")
@loginrequired
def billing_initial_GET():
    return render_template("billing-initial.html")

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
        return redirect(url_for("billing.billing_GET"))
    return redirect(url_for("billing.new_payment_GET"))

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
        customer = stripe.Customer.create(
                description="~" + current_user.username,
                email=current_user.email,
                card=token)
        current_user.stripe_customer = customer.id
        current_user.payment_due = datetime.utcnow() + timedelta(seconds=-1)
    else:
        new_customer = False
        customer = stripe.Customer.retrieve(current_user.stripe_customer)
        customer.sources.create(token)
    # TODO: Add audit log entry with last 4 of CC
    current_user.payment_interval = PaymentInterval(term)
    success, details = charge_user(current_user)
    print(details)
    if not success:
        return render_template("new-payment.html",
                amount=current_user.payment_cents, error=details)
    db.session.commit()
    if new_customer:
        return redirect(onboarding_redirect)
    session["message"] = "Your payment method was updated."
    return redirect(url_for("billing.billing_GET"))
