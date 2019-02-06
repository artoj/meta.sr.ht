import pkg_resources
from flask import Blueprint
from metasrht.blueprints.api.delegate import delegate
from metasrht.blueprints.api.keys import keys
from metasrht.blueprints.api.user import user
from srht.flask import csrf_bypass

def register_api(app):
    app.register_blueprint(delegate)
    app.register_blueprint(keys)
    app.register_blueprint(user)

    csrf_bypass(delegate)
    csrf_bypass(keys)
    csrf_bypass(user)

    @app.route("/api/version")
    def version():
        try:
            dist = pkg_resources.get_distribution("metasrht")
            return { "version": dist.version }
        except:
            return { "version": "unknown" }
