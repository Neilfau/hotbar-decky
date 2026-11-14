# Installs a fake decky module so main.py can be imported outside Decky Loader.
import logging
import sys
import types
from pathlib import Path

fake_decky = types.ModuleType("decky")
fake_decky.logger = logging.getLogger("decky-test")
sys.modules["decky"] = fake_decky

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
