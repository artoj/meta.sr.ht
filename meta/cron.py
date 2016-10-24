#!/usr/bin/env python3
from meta.config import _cfg, _cfgi
from meta.db import db, init_db
from meta.audit import expire_audit_log
import sys

init_db()

if sys.argv[1] == 'daily':
    print("Running daily cron")
    print("Expiring old audit log entires")
    expire_audit_log()
    print("Done.")
