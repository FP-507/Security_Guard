"""Launcher that forces fresh import of app.py, bypassing .pyc cache."""
import sys, os, importlib, importlib.util

# Force Python to reload source, not bytecode
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

# Insert the app directory into path
app_dir = os.path.dirname(os.path.abspath(__file__))
if app_dir not in sys.path:
    sys.path.insert(0, app_dir)

# Invalidate all cached module sources
importlib.invalidate_caches()

# Load app.py as fresh source (no .pyc)
spec = importlib.util.spec_from_file_location(
    "__main__",
    os.path.join(app_dir, "app.py"),
    submodule_search_locations=[],
)
module = importlib.util.module_from_spec(spec)
sys.modules["__main__"] = module

# Force source loader (not bytecode)
spec.loader.exec_module(module)
