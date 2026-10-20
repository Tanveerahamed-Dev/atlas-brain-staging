import sys
STARTUP = tuple(sorted(sys.modules))

import json
import multiprocessing as mp
from concurrent.futures import ProcessPoolExecutor


def worker():
    return STARTUP


if __name__ == "__main__":
    with ProcessPoolExecutor(max_workers=1, mp_context=mp.get_context("spawn")) as pool:
        child = pool.submit(worker).result(timeout=120)
    print(json.dumps({"coordinator": STARTUP, "worker": child, "version": sys.version,
                      "no_site": sys.flags.no_site, "isolated": sys.flags.isolated,
                      "venv": sys.prefix != sys.base_prefix}, sort_keys=True))
