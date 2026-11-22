# Submitting HotBar to the Decky plugin store

This is the drafted pull request for
[decky-plugin-database](https://github.com/SteamDeckHomebrew/decky-plugin-database).
It has not been opened. Opening it is the maintainer's decision.

Sources, read on 2026-11-22: the database README and its
`.github/PULL_REQUEST_TEMPLATE/plugin_addition.md`, the wiki pages
`plugin-dev/submitting-plugins.md` and `plugin-dev/review-and-testing.md`
(from the `SteamDeckHomebrew/wiki` repository), the `decky-plugin-template`
README, `plugin.json` and `package.json`, the database's
`.github/workflows/build-plugins.yml`, and `src/cli/plugin/build.rs` in
`SteamDeckHomebrew/cli`. The database has no `CONTRIBUTING.md`.

## Before opening the pull request

### Generative AI policy

The `submitting-plugins` wiki page says the store does not accept any plugin
that uses LLM-based code. The pull request template is looser: its box reads
"Generative AI was NOT used to write a majority of the code I am submitting",
and it warns that pull requests that do not follow the template may be denied
for suspected AI use. The wiki rule is the stricter one, and reviewers can
apply it.

Every code commit in this repository's public history carries a
`Co-Authored-By: Claude` trailer, so reviewers can see that an AI model
co-wrote the code. Under the wiki rule as written, the store is not open to
this plugin. Whether to submit anyway, for example after asking the Loader
Team, is the maintainer's decision. The ZIP install from a GitHub release
(see the README) works without the store.

### Checklist

- [ ] The plugin meets the wiki's rule of no LLM-based code, or the Loader
      Team has said it can be submitted. The template's "majority" box alone
      is not enough.
- [ ] HotBar works on a Steam Deck in Game Mode on SteamOS Stable or Beta:
      pairing, typing, shortcuts, pointer, sleep and wake, restart.
- [ ] `package.json` `version` is bumped for this submission (0.1.0 for the
      first one).
- [ ] `dev` is merged into `release` and tagged `v<version>`. The Release
      workflow attaches `HotBar.zip` to the GitHub release.
- [ ] `pnpm-lock.yaml` is on `lockfileVersion: '9.0'` (the store CI uses
      pnpm 9).
- [ ] `LICENSE` is in the repository root and keeps the template's original
      copyright line.
- [ ] Third-party notices: `qrcode.react` (ISC) keeps its licence header in
      `dist/index.js`. The panel icon comes from `react-icons` (MIT), which
      redistributes Font Awesome Free icons (CC BY 4.0). Decide whether that
      needs a credit in the README.
- [ ] No unused `backend/`, `assets/` or `defaults/` folders. `assets/` holds
      the store image that `plugin.json` points to and the icon the README
      shows. Review step 7 only names `icon.png` as a reason to keep
      `assets/`, so a reviewer may ask about it.
- [ ] The store image URL in `plugin.json` loads:
      `https://raw.githubusercontent.com/Neilfau/hotbar-decky/dev/assets/store-image.png`.
      It follows the `dev` branch, so a later change to the image there
      changes the store card.
- [ ] Optional but it raises priority: test two other open plugin pull
      requests and leave a report on each.
- [ ] Search the store for plugins that already turn a phone into a keyboard
      or pointer. If one exists, the summary must say how HotBar differs.

## Steps

1. Fork `SteamDeckHomebrew/decky-plugin-database` on GitHub.
2. Clone the fork and create a branch:

   ```bash
   git clone https://github.com/<your-account>/decky-plugin-database.git
   ```

   ```bash
   cd decky-plugin-database && git checkout -b add-hotbar
   ```

3. Add HotBar as a submodule in `plugins/HotBar`. The folder name becomes the
   ZIP name and the plugin folder on the Deck, so it matches `plugin.json`'s
   name:

   ```bash
   git submodule add https://github.com/Neilfau/hotbar-decky.git plugins/HotBar
   ```

4. Point the submodule at the release commit:

   ```bash
   git -C plugins/HotBar checkout v0.1.0
   ```

5. Commit and push:

   ```bash
   git add .gitmodules plugins/HotBar
   ```

   ```bash
   git commit -m "Add HotBar to Plugin Store"
   ```

   ```bash
   git push -u origin add-hotbar
   ```

6. Open the pull request against `main` with the plugin addition template, by
   adding `?template=plugin_addition.md` to the compare URL, then replace the
   body with the text below.
7. Once the plugin is on the testing store, share
   [docs/testing.md](testing.md) with testers and link their reports in the
   pull request. Do not tick the third-party testing box yourself.

The store CI builds the ZIP from the submodule commit with
`decky plugin build`. For pull request builds it appends the commit hash to
the version. `pnpm run package` in this repository produces the same layout,
so a local ZIP shows what the store will ship.

## Updating later

Bump `version` in `package.json`, merge to `release` and tag. Then in the
database fork:

```bash
git -C plugins/HotBar fetch --tags && git -C plugins/HotBar checkout v<version>
```

```bash
git add plugins/HotBar && git commit -m "Update HotBar to <version>"
```

Open the pull request with the `plugin_update.md` template, titled
"Update HotBar to <version>".

## Pull request text

Title: `Add HotBar to Plugin Store`

Body, following `plugin_addition.md`. The boxes are left for the maintainer to
tick, and the Preview testing line is removed because HotBar uses the Python
backend and the React frontend only.

```markdown
# Add HotBar to Plugin Store

HotBar turns a phone or tablet into a keyboard, shortcut pad and pointer for
games on the Steam Deck. It is the Deck side of the HotBar phone app.

- The Quick Access panel shows a QR code. The app scans it and the two agree
  a key (X25519) that only they hold. Each paired device has its own key and
  can be removed alone in the panel.
- The plugin listens on the local network only. Every message after pairing
  is encrypted and authenticated with ChaCha20-Poly1305, and replays are
  rejected. Unauthenticated connections are dropped.
- Each command becomes one key press, one line of text or one pointer event,
  through a virtual keyboard and mouse on `/dev/uinput`. This is why the
  plugin needs the `root` flag. It reads no game files.
- The plugin writes an avahi service file so the app can find the Deck again
  when its address changes, and removes it when it stops or is uninstalled.
- Logs hold no typed text, key codes or keys.

The backend is Python on the standard library plus the `aiohttp` that Decky
bundles. The crypto is pure Python because Decky's Python cannot load native
wheels, and it is checked against the RFC test vectors. There is no custom
backend and no binary.

Source: https://github.com/Neilfau/hotbar-decky (BSD-3-Clause)
Tester guide: https://github.com/Neilfau/hotbar-decky/blob/dev/docs/testing.md

## Task Checklist

### Developer

- [ ] I am the original author or an authorized maintainer of this plugin.
- [ ] I have abided by the licenses of the libraries I am utilizing, including attaching license notices where appropriate.
- [ ] Generative AI was NOT used to write a majority of the code I am submitting.

### Plugin

- [ ] I have verified that my plugin works properly on the Stable and Beta update channels of SteamOS.
- [ ] I have verified my plugin is unique or provides more/alternative functionality to a plugin already on the store.

### Backend

- **No**: I am using a custom backend other than Python.
- **No**: I am using a tool or software from a 3rd party FOSS project that does not have it's dependencies [statically linked](https://en.wikipedia.org/wiki/Static_library).
- **No**: I am using a custom binary that has all of it's dependencies statically linked.

### Community

- [ ] I have tested and left feedback on two other [pull requests][pulls] for new or updating plugins.
- [ ] I have commented links to my testing report in this PR.

## Testing

- [ ] Tested by a third party on SteamOS Stable or Beta update channel.

[pulls]: https://github.com/steamdeckHomebrew/decky-plugin-database/pulls?q=is%3Apr+is%3Aopen+sort%3Acreated-desc+-status%3Afailure+-draft%3Atrue+-author%3A%40me
```
