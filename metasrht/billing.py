import stripe
from datetime import datetime, timedelta
from enum import Enum
from metasrht.audit import audit_log
from metasrht.types import User, UserType, PaymentInterval, Invoice
from srht.config import cfg
from srht.database import db

stripe.api_key = cfg("meta.sr.ht::billing", "stripe-secret-key")

class ChargeResult(Enum):
    success = "success"
    failed = "failed"
    cancelled = "cancelled"
    delinquent = "delinquent"
    account_current = "account_current"

def charge_user(user):
    if user.user_type == UserType.active_free:
        return ChargeResult.account_current, "Your account is exempt from payment."
    if user.payment_due >= datetime.utcnow():
        return ChargeResult.account_current, "Your account is current."
    desc = f"{cfg('sr.ht', 'site-name')} {user.payment_interval.value} payment"
    if user.payment_cents == 0:
        # They cancelled their payment and their current term is up
        user.user_type = UserType.active_non_paying
        return ChargeResult.cancelled, "Your paid service has been cancelled."
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
                details="charged ${:.2f}".format(amount / 100))
    except stripe.error.CardError as e:
        details = e.json_body["error"]["message"]
        if user.user_type == UserType.active_delinquent:
            # Don't email them twice
            return ChargeResult.delinquent, "Your account payment is delinquent"
        user.user_type = UserType.active_delinquent
        return ChargeResult.failed, details
    except:
        return ChargeResult.failed, "Your payment failed. Contact support."
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
        invoice.valid_thru = datetime.utcnow()
        leapday = (invoice.valid_thru.month == 2
                and invoice.valid_thru.day == 29)
        invoice.valid_thru = datetime(year=invoice.valid_thru.year + 1,
                month=invoice.valid_thru.month, day=(invoice.valid_thru.day - 1
                    if leapday else invoice.valid_thru.day))
        user.payment_due = invoice.valid_thru
    user.user_type = UserType.active_paying
    db.session.commit()
    return ChargeResult.success, "Your card was successfully charged. Thank you!"
