from meta.app import app
from meta.config import _cfg, _cfgi

import os

app.static_folder = os.path.join(os.getcwd(), "static")

if __name__ == '__main__':
    app.run(host=_cfg("debug", "debug-host"),
            port=_cfgi("debug", "debug-port"),
            debug=True)
