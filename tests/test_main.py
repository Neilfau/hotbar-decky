# Checks that the backend module imports and exposes the Plugin class.
import main


def test_main_exposes_plugin_class():
    assert isinstance(main.Plugin, type)
