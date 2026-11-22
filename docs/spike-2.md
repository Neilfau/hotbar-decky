# Spike 2: device probe runbook

`tools/spike_probe.py` settles, in one run on a Steam Deck, the facts the
tests on a Mac cannot: what Decky's Python offers, how fast the plugin's
pure-Python crypto is there, whether the plugin can use `/dev/uinput`, what
it can type, whether avahi announces the plugin, and where its log is.

The probe runs on the Deck's system Python. Decky runs the plugin with its
own bundled Python, so for that interpreter the probe reads the self-check
lines the plugin writes to its log at start-up. Install and start the plugin
before running the probe.

## What the probe changes

- It writes `/etc/avahi/services/hotbar-probe.service` (type
  `_hotbarprobe._tcp`, port 9), waits for avahi to announce it, and removes
  it again. Only if avahi does not announce it on its own does the probe run
  `avahi-daemon --reload` and check again.
- At the end it types four test lines into the focused window through the
  plugin's own input code. It never presses Enter. `--no-type` skips this.
- It reads the plugin log and the plugin manifests. It never reads the
  plugin's device file, which holds the pairing keys.

## Before you start

1. Install HotBar on the Deck (testing store or install from ZIP) and check
   the panel does not say "Not running". This writes the self-check lines.
2. Set a password for the `deck` user if it has none (`passwd` in Konsole),
   because the probe needs `sudo`.
3. Choose where the typed lines go:
   - **Desktop Mode:** open KWrite and click into its window. Run the probe
     over SSH from the Mac, so Konsole does not take the keys.
   - **Game Mode:** start a game, open its text chat, and run the probe over
     SSH. This is the case that matters for HotBar.
   Running the probe in Konsole on the Deck itself types the lines into
   Konsole, which shows them but tests nothing new.
4. Have the Mac on the same network as the Deck, for the discovery check.
5. For SSH, start the SSH server once in Konsole:
   `sudo systemctl enable --now sshd`, then `ssh deck@steamdeck.local` from
   the Mac.

## Run it

Get the repository onto the Deck, then run the probe with `sudo`:

```bash
git clone https://github.com/Neilfau/hotbar-decky.git
```

```bash
sudo python3 hotbar-decky/tools/spike_probe.py 2>&1 | tee spike-2.txt
```

When it prints `typing in 10...`, put the cursor in the text field you chose
in step 3. `--countdown 20` gives more time.

On the Mac, while the plugin is running on the Deck:

```bash
dns-sd -B _hotbar._tcp local.
```

The probe also prints a `dns-sd -L` line with the Deck's host name, which
resolves the address and port. Stop each `dns-sd` with Ctrl-C.

To copy the output to the Mac:

```bash
scp deck@steamdeck.local:spike-2.txt .
```

## Results

Fill in from the probe output. Section numbers match the probe's headings.

| # | Question | Probe line | Result |
|---|----------|------------|--------|
| 1a | Decky's Python version | `decky python:` | |
| 1b | `hashlib` SHA-256, `hmac`, `secrets`, `fcntl`, `ctypes`, `aiohttp` in Decky's Python | `decky hashlib_sha256:` and the lines after it | |
| 1c | Every other module the plugin imports loads in Decky's Python | `decky python loaded every module above:` | |
| 1d | System Python version, and modules missing there | `system python:`, `missing in system python:` | |
| 2a | One X25519 key agreement in Decky's Python | `decky x25519_shared` | |
| 2b | One pairing in Decky's Python (estimate) | `decky pairing estimate:` | |
| 2c | Sealing a 512-byte message in Decky's Python | `decky chacha20poly1305_seal_512:` | |
| 2d | Pairing, seal and open of 512 bytes in system Python | `system python pairing:`, `seal_512:`, `open_512:` | |
| 3a | uid the plugin runs as | `plugin effective uid:` | |
| 3b | uid of Decky's loader | `decky loader effective uid:` | |
| 3c | The plugin can open `/dev/uinput` | `plugin opened /dev/uinput:` | |
| 3d | The plugin created its virtual keyboard and pointer | `plugin created its virtual keyboard and pointer:` | |
| 3e | `/dev/uinput` mode, owner and group | `/dev/uinput:` | |
| 4a | Plain ASCII went through, and looks right on screen | `plain ASCII:` | |
| 4b | Every printable ASCII symbol went through, and looks right on screen | `password symbols:` | |
| 4c | Accented letters (expected: refused whole) | `accented letters:` | |
| 4d | Emoji (expected: refused whole) | `emoji:` | |
| 4e | Where the lines were typed (Desktop KWrite, or which game) | | |
| 4f | Steam's on-screen keyboard | `steam keyboard:` | not applicable |
| 5a | avahi-daemon is running | `avahi-daemon running:` | |
| 5b | The plugin's service file is present | `/etc/avahi/services/hotbar.service:` | |
| 5c | `_hotbar._tcp` resolves on the Deck | `_hotbar._tcp on this Deck:` | |
| 5d | avahi picks up a new service file without a restart | `pickup without restart:` | |
| 5e | `dns-sd -B _hotbar._tcp` on the Mac lists the Deck | (Mac) | |
| 5f | `dns-sd -L` on the Mac gives the Deck's address and port | (Mac) | |
| 6a | Plugin log file | `log with the self-check lines:` | |
| 6b | Plugin folder | `plugin folder:` | |
| — | SteamOS version and channel, Deck model (LCD or OLED), Decky version, HotBar version | (Settings) | |

## Reading the results

- **No self-check lines.** Rows 1a to 3c say "unknown". The plugin has not
  started, or its log is somewhere the probe did not look. Check row 6a and
  `journalctl -b -u plugin_loader --no-pager | grep -i hotbar`.
- **1c.** The self-check runs after `main.py` and every plugin module have
  been imported, so its lines in the log prove each module listed loads in
  Decky's Python. An `import errors in the plugin log:` block means a module
  failed in an earlier start.
- **2b.** The plugin's share of a pairing is two X25519 operations (its key
  pair and the shared secret) and three HKDF calls, so the estimate doubles
  the logged key agreement. The system Python line measures the same work
  directly.
- **4a and 4b.** "sent" means the plugin accepted the line and wrote the key
  events. Compare the screen with the `expected on screen:` line. A wrong
  symbol points at a keyboard layout other than US.
- **4c and 4d.** The plugin types US-layout ASCII only and refuses a whole
  line that holds any other character, so nothing of these lines is typed.
- **5d "no".** If the reload line says it was then announced, the plugin has
  to ask avahi to reload after it writes its service file.
- **5c yes, 5e no.** avahi announces on the Deck but the Mac does not see it:
  check the network (guest Wi-Fi, client isolation) before the plugin.

## Clean up

```bash
rm -rf hotbar-decky spike-2.txt
```

The probe removes its own service file, also when it stops with an error. If
it was killed, remove the file by hand:

```bash
sudo rm -f /etc/avahi/services/hotbar-probe.service
```
