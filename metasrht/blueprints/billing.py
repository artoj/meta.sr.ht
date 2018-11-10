from flask import Blueprint, render_template
from srht.flask import loginrequired

billing = Blueprint('billing', __name__)

@billing.route("/billing")
@loginrequired
def billing_GET():
    return render_template("billing.html")

@billing.route("/billing/initial")
@loginrequired
def billing_initial_GET():
    return render_template("billing-initial.html")
