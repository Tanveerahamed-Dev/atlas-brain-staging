import sys
STARTUP_MODULES = tuple(sorted(sys.modules))
from pathlib import Path
ROOT = str(Path(__file__).resolve().parents[1])
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
from spike.safety import install
install()
from spike.admission import install as admit
admit(STARTUP_MODULES, "worker" if __name__ == "__mp_main__" else "coordinator")

if __name__ == "__main__":
    from spike.runtime import main
    main(STARTUP_MODULES)
