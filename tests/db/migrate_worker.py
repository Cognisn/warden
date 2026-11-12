"""Run ``warden.db.migrate`` from a separate process, as a replica would.

usage: migrate_worker.py DSN START_EPOCH

Prints ``ready <epoch>`` once imported, waits until START_EPOCH so every
worker begins together, then migrates.
"""

import sys
import time

from warden.db import migrate

dsn, start = sys.argv[1], float(sys.argv[2])
print(f"ready {time.time()}", flush=True)
delay = start - time.time()
if delay > 0:
    time.sleep(delay)
migrate(dsn)
print("done", flush=True)
