# Testing HotBar from the Decky testing store

Thank you for testing. HotBar is in review for the Decky plugin store. Until
it is approved it is only on the testing store, and the Decky team needs test
reports from people with a Steam Deck before they merge it.

Decky asks for tests on the **Stable** or **Beta** SteamOS update channel.
HotBar has a Python backend and no custom binaries, so Preview is not needed.

## What you need

- A Steam Deck with [Decky Loader](https://github.com/SteamDeckHomebrew/decky-loader)
  installed.
- A phone or tablet with the HotBar app.
- The Deck and the phone on the same Wi-Fi network. Guest networks often block
  devices from reaching each other, so use a home network if you can.
- A game with a text chat, or any text field you can type into in Game Mode.

## Install from the testing store

1. In Game Mode, press the Quick Access button (`...`) and open the Decky tab.
2. Open Decky's settings (the gear), then General.
3. Set Store Channel to Testing.
4. Go back, open the store (the shop icon) and find HotBar.
5. Choose Install and confirm. HotBar appears in the Decky tab.

Set Store Channel back to Default when you are done testing.

## Test steps

Do these in Game Mode. Note anything that fails or looks wrong.

1. **Panel opens.** Open HotBar in the Decky tab. The status line says how
   many devices are paired and does not say "Not running".
2. **Pairing.** With no device paired, a QR code shows as soon as the panel
   opens. Scan it with the HotBar app. The phone appears in the panel's device list within a few
   seconds, and shows Connected.
3. **QR expiry.** Choose Pair another device and wait two minutes without
   scanning. The panel says the QR code expired.
4. **Typing.** Start a game and open its text chat, or any text field. Send a
   line from the app. It appears once, with the right characters. Try capital
   letters, digits and symbols such as `@ # ! ? / ( )`.
5. **Shortcuts.** Send a few single keys or shortcuts from the app. Each one
   presses once.
6. **Pointer.** If the app has a trackpad, move the pointer and click. The
   pointer moves in the direction you swipe.
7. **Sleep and wake.** Put the Deck to sleep, wake it, and send a line again.
   The app reconnects, possibly after a few seconds.
8. **Restart.** Restart the Deck. Without pairing again, send a line. The app
   finds the Deck and the line arrives.
9. **Remove a device.** In the panel, choose Remove next to the phone and
   confirm. The app can no longer send input. Pair again to continue.
10. **Uninstall.** Optional. Uninstall HotBar from Decky's settings. The Deck
    keeps working normally.

## What to report

Post your report as a comment on the HotBar pull request in
[decky-plugin-database](https://github.com/SteamDeckHomebrew/decky-plugin-database/pulls),
or as an issue in [hotbar-decky](https://github.com/Neilfau/hotbar-decky/issues).
Please include:

- SteamOS version and update channel (Settings, System).
- Decky Loader version (Decky settings, General, About).
- HotBar version (shown in Decky's plugin list).
- Steam Deck model (LCD or OLED).
- Phone or tablet model and OS version.
- Which steps passed and which failed. For a failure: what you did, what you
  expected and what happened.
- The game you typed into, if a step failed there.
- Logs, collected as below.

Please do not include anything you typed in a report. Typed text can be a
password. The plugin never writes typed text to its log.

## Collecting logs

You need a terminal on the Deck: Konsole in Desktop Mode, or SSH from a
computer.

The plugin log, including the start-up self-check:

```bash
ls -t /home/deck/homebrew/logs/HotBar/
```

```bash
tail -n 200 "/home/deck/homebrew/logs/HotBar/$(ls -t /home/deck/homebrew/logs/HotBar/ | head -n 1)"
```

Decky Loader's own log for the current boot:

```bash
journalctl -b -u plugin_loader --no-pager | tail -n 300
```

The diagnose tool checks root access, `/dev/uinput` and network discovery.
It needs a copy of this repository on the Deck and `sudo`, which needs a
password set for the `deck` user (`passwd`):

```bash
git clone https://github.com/Neilfau/hotbar-decky.git
```

```bash
sudo python3 hotbar-decky/tools/diagnose.py
```

Paste the output of these commands into your report as text. See
[Troubleshooting](../README.md#troubleshooting) in the README for what the
diagnose output means.
