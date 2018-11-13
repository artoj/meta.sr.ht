import stripe
from datetime import datetime, timedelta
from srht.config import cfg
from srht.database import db
from metasrht.audit import audit_log
from metasrht.types import User, UserType, PaymentInterval, Invoice

stripe.api_key = cfg("meta.sr.ht::billing", "stripe-secret-key")

def charge_user(user):
    if user.user_type == UserType.active_free:
        return True, "Your account is exempt from payment."
    if user.payment_due >= datetime.utcnow():
        return True, "Your account is current."
    desc = f"{cfg('sr.ht', 'site-name')} {user.payment_interval.value} payment"
    if user.payment_cents == 0:
        # They cancelled their payment and their current term is up
        user.user_type = UserType.active_non_paying
        return True, "Your paid service has been cancelled."
    try:
        amount = user.payment_cents
        if user.payment_interval == PaymentInterval.yearly:
            amount = amount * 10 # Apply yearly discount
        # TODO: Multiple currencies
        charge = stripe.Charge.create(
            amount=amount,
            currency="usd",
            customer=user.stripe_customer,
            description=desc)
        audit_log("billing",
                details="charged ${:.2f}".format(user.payment_cents / 100))
    except stripe.error.CardError as e:
        details = e.json_body["error"]["message"]
        user.user_type = UserType.active_delinquent
        return False, details
    invoice = Invoice()
    invoice.cents = amount
    invoice.user_id = user.id
    try:
        invoice.source = f"{charge.source.brand} ending in {charge.source.last4}"
    except:
        # Not a credit card? dunno how this works
        invoice.source = charge.source.stripe_id
    db.session.add(invoice)
    if user.payment_interval == PaymentInterval.monthly:
        invoice.valid_thru = datetime.utcnow() + timedelta(days=30)
        user.payment_due = invoice.valid_thru
    else:
        invoice.valid_thru = datetime.utcnow() + timedelta(days=365)
        user.payment_due = invoice.valid_thru
    user.user_type = UserType.active_paying
    return True, "Your card was successfully charged. Thank you!"
