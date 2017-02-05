from flask import Blueprint, render_template
from meta.common import loginrequired

billing = Blueprint('billing', __name__)

@billing.route("/billing")
@loginrequired
def billing_GET():
    return render_template("billing.html")
