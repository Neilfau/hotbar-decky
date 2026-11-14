# hotbar-decky

HotBar is a plugin for [Decky Loader](https://github.com/SteamDeckHomebrew/decky-loader),
the plugin loader for SteamOS on the Steam Deck. Together with the HotBar app
it turns a phone or tablet into a keyboard, shortcut pad and pointer for games.

The plugin does three things:

- It pairs devices. The Quick Access panel shows a QR code, the app scans it,
  and both sides agree on a key that only they hold.
- It listens on the local network for encrypted commands from paired devices.
- It carries out each command as keyboard or pointer input through
  `/dev/uinput`: one key press, one line of text, or one pointer event.

Everything else, such as key maps and profiles, lives in the app.

It is based on the official
[Decky plugin template](https://github.com/SteamDeckHomebrew/decky-plugin-template).

## Security notes

- The plugin runs as root, because creating input devices through
  `/dev/uinput` needs it (`_root` in `plugin.json`).
- The listener accepts connections from private, link-local and loopback
  IPv4 addresses only.
- Every paired device has its own key and can be removed alone in the panel.
  Removal takes effect on that device's next message.
- Keys are stored in `devices.json` in the plugin's settings directory, with
  mode 0600.
- Traffic is plain HTTP and WebSocket. Each message is sealed with
  ChaCha20-Poly1305 under a key derived for that message, and replays are
  rejected.
- The plugin never logs what is sent: no text, key codes, pointer data, keys
  or tokens.
- X25519, HKDF-SHA256 and ChaCha20-Poly1305 are written in pure Python on the
  standard library, because Decky's Python cannot load native wheels. They are
  checked against the RFC test vectors. They are not constant time.

## Layout

- `src/`: the Quick Access panel (React, built with Rollup).
- `main.py`: the Decky entry point and the calls the panel makes.
- `py_modules/hotbar/`: the backend.
  - `crypto.py`, `envelope.py`: primitives and the sealed message format.
  - `pairing.py`, `store.py`: pairing sessions and the device key file.
  - `messages.py`, `receiver.py`: message validation, replay protection and
    rate limits.
  - `input/`: the key table and the uinput devices.
  - `server.py`: the HTTP and WebSocket endpoints.
- `tests/`: Python tests, run with a stand-in for the `decky` module and fake
  input devices. `tests/vectors/` holds the protocol test vectors.
- `tools/dev_server.py`: runs the backend on a development machine with fake
  input devices.

## Requirements

- Node.js 22 with Corepack (ships with Node.js).
- [uv](https://docs.astral.sh/uv/) for the Python tests.

The backend uses the Python standard library and `aiohttp`, which Decky
Loader bundles. The panel uses
[qrcode.react](https://github.com/zpao/qrcode.react) (ISC) to draw the QR
code.

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
uv run --python 3.14 --with pytest --with aiohttp python -m pytest
```

## Run the backend without a Steam Deck

```bash
uv run --python 3.14 --with aiohttp python tools/dev_server.py
```

It prints a pairing link and then one line per received action. No input is
injected.

## Licence

BSD-3-Clause. See [LICENSE](LICENSE).
