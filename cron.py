#!/usr/bin/env python3
from srht.config import cfg, cfgi
from srht.database import DbSession
db = DbSession(cfg("sr.ht", "connection-string"))
import meta.types
db.init()

from meta.audit import expire_audit_log
import sys

if sys.argv[1] == 'daily':
    print("Running daily cron")
    print("Expiring old audit log entires")
    expire_audit_log()
    print("Done.")
