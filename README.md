# hotbar-decky

HotBar is a plugin for [Decky Loader](https://github.com/SteamDeckHomebrew/decky-loader),
the plugin loader for SteamOS on the Steam Deck. It adds a HotBar panel to the
Quick Access menu.

The plugin is at an early stage: the panel currently shows a placeholder and
the Python backend only implements the Decky lifecycle hooks.

It is based on the official
[Decky plugin template](https://github.com/SteamDeckHomebrew/decky-plugin-template).

## Layout

- `src/index.tsx`: the Quick Access panel (React, built with Rollup).
- `main.py`: the Python backend that Decky Loader runs.
- `plugin.json`: plugin metadata read by Decky Loader.
- `tests/`: Python tests, run with a stand-in for the `decky` module.

## Requirements

- Node.js 22 with Corepack (ships with Node.js).
- [uv](https://docs.astral.sh/uv/) for the Python tests.

## Build the panel

```bash
corepack enable pnpm
```

```bash
pnpm install --frozen-lockfile
```

```bash
pnpm run build
```

The output is `dist/index.js`.

## Run the tests

Type-check the panel:

```bash
pnpm exec tsc --noEmit
```

Run the Python tests:

```bash
uv run --python 3.14 --with pytest python -m pytest
```

## Licence

BSD-3-Clause. See [LICENSE](LICENSE).
