import stripe
from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, session, redirect
from flask import url_for, abort, Response
from flask_login import current_user
from jinja2 import escape
from srht.database import db
from srht.config import cfg
from srht.flask import loginrequired
from srht.validation import Validation
from metasrht.audit import audit_log
from metasrht.billing import charge_user
from metasrht.types import User, UserType, PaymentInterval, Invoice
from weasyprint import HTML, CSS

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
    return render_template("billing.html", message=message, customer=customer)

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
        try:
            customer = stripe.Customer.create(
                    description="~" + current_user.username,
                    email=current_user.email,
                    card=token)
            current_user.stripe_customer = customer.id
            current_user.payment_due = datetime.utcnow() + timedelta(seconds=-1)
        except stripe.error.CardError as e:
            details = e.json_body["error"]["message"]
            return render_template("new-payment.html",
                    amount=current_user.payment_cents, error=details)
    else:
        new_customer = False
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
    if new_customer:
        return redirect(onboarding_redirect)
    session["message"] = "Your payment method was updated."
    return redirect(url_for("billing.billing_GET"))

@billing.route("/billing/cancel", methods=["POST"])
@loginrequired
def cancel_POST():
    current_user.payment_cents = 0
    db.session.commit()
    audit_log("billing", "Plan cancelled (will not renew)")
    return redirect(url_for("billing.billing_GET"))

@billing.route("/billing/invoice/<invoice_id>")
@loginrequired
def invoice_GET(invoice_id):
    invoice = Invoice.query.filter(Invoice.id == invoice_id).one_or_none()
    if not invoice:
        abort(404)
    if (invoice.user_id != current_user.id 
            and current_user.user_type != UserType.admin):
        abort(401)
    return render_template("billing-invoice.html", invoice=invoice)

@billing.route("/billing/invoice/<invoice_id>", methods=["POST"])
@loginrequired
def invoice_POST(invoice_id):
    invoice = Invoice.query.filter(Invoice.id == invoice_id).one_or_none()
    if not invoice:
        abort(404)
    if (invoice.user_id != current_user.id 
            and current_user.user_type != UserType.admin):
        abort(401)
    valid = Validation(request)
    bill_to = valid.optional("address-to")
    if not bill_to:
        bill_to = "~" + invoice.user.username
    bill_from = [l for l in [
        cfg("meta.sr.ht::billing", "address-line1", default=None),
        cfg("meta.sr.ht::billing", "address-line2", default=None),
        cfg("meta.sr.ht::billing", "address-line3", default=None),
        cfg("meta.sr.ht::billing", "address-line4", default=None)
    ] if l]

    # Split bill_to to first row (rendered as heading) and others
    [bill_from_head, *bill_from_tail] = bill_from or [None]

    html = render_template("billing-invoice-pdf.html",
        invoice=invoice,
        amount=f"${invoice.cents / 100:.2f}",
        source=invoice.source,
        created=invoice.created.strftime("%Y-%m-%d"),
        valid_thru=invoice.valid_thru.strftime("%Y-%m-%d"),
        bill_to=bill_to,
        bill_from_head=bill_from_head,
        bill_from_tail=bill_from_tail)

    pdf = HTML(string=html).write_pdf()

    filename = f"invoice_{invoice.id}.pdf"
    headers = [('Content-Disposition', f'attachment; filename="{filename}"')]
    return Response(pdf, mimetype="application/pdf", headers=headers)
