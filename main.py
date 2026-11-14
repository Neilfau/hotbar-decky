# Decky backend entry point for the HotBar plugin.
import decky


class Plugin:
    # Runs in a task when the plugin is loaded.
    async def _main(self):
        decky.logger.info("HotBar loaded")

    # Runs when the plugin is stopped but not removed.
    async def _unload(self):
        decky.logger.info("HotBar unloaded")

    # Runs after _unload when the plugin is uninstalled.
    async def _uninstall(self):
        decky.logger.info("HotBar uninstalled")

    # Runs before _main to migrate old data.
    async def _migration(self):
        pass
