<div align="center">

# 🔒 LockHTML

**Turn any HTML file into a PIN-protected document — optionally viewable only once.**

Encrypts with AES-256-GCM, unlocks in the browser, runs everywhere.

[![CI](https://github.com/drsamonline/lockhtml/actions/workflows/ci.yml/badge.svg)](https://github.com/drsamonline/lockhtml/actions/workflows/ci.yml)
[![Deploy GUI](https://github.com/drsamonline/lockhtml/actions/workflows/pages.yml/badge.svg)](https://github.com/drsamonline/lockhtml/actions/workflows/pages.yml)
[![Live GUI](https://img.shields.io/badge/live%20GUI-open%20in%20browser-5a86ff?logo=html5&logoColor=white)](https://drsamonline.github.io/lockhtml/)
[![License: MIT](https://img.shields.io/badge/license-MIT-33d17a.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-3776ab?logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-8957e5)](#)
[![Crypto](https://img.shields.io/badge/crypto-AES--256--GCM-ff6b6b)](#how-it-works)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![GitHub stars](https://img.shields.io/github/stars/drsamonline/lockhtml?style=social)](https://github.com/drsamonline/lockhtml/stargazers)
[![Last commit](https://img.shields.io/github/last-commit/drsamonline/lockhtml)](https://github.com/drsamonline/lockhtml/commits)

</div>

---

**LockHTML** takes an ordinary `.html` file, encrypts it with a key derived from a PIN,
and gives you back a single self-contained `.html` file. Anyone who opens it is asked
for the PIN; enter it and the document renders in the browser. Choose **one-time view**
and the document expires the moment it has been opened once.

No server. No accounts. No uploads. The encrypted file is a normal web page you can
email, message or put on a USB stick.

## ✨ Features

- 🔐 **Real encryption** — AES-256-GCM, key derived with PBKDF2-SHA256 (250,000 iterations by default).
- 👁️ **One-time view** — optionally expire the document after the first successful open.
- 🖥️ **Cross-platform CLI** — one command on Windows, Linux and macOS.
- 🌐 **HTML GUI** — a single file that runs in any browser on any OS, and is also
  [live on the web](https://drsamonline.github.io/lockhtml/). 100% client-side.
- 📦 **Self-contained output** — the locked file needs no internet, no install, no app.
- 🔁 **Reversible** — `lockhtml unlock` recovers the original with the PIN.
- 🧩 **Zero runtime for the recipient** — any modern browser opens a locked file.

## 🚀 Quick start

### GUI (no install)

Open the live app → **<https://drsamonline.github.io/lockhtml/>** — or run it locally with
the CLI (below). Drag in your HTML, type a PIN, download the locked file.

### CLI

```bash
pip install lockhtml
```

```bash
# Lock one file
lockhtml lock report.html --pin 4821

# Lock it as a one-time-view document
lockhtml lock report.html --pin 4821 --one-time

# Lock a whole folder of pages
lockhtml lock *.html --pin 4821 --outdir locked/

# Recover the original (you need the PIN)
lockhtml unlock report.locked.html --pin 4821 -o report.html

# Open the browser GUI
lockhtml gui
```

That produces `report.locked.html` — a single file that asks for `4821` when opened.

> **Tip:** share the PIN over a *different* channel than the file.

## 🖥️ The GUI

The GUI is one self-contained HTML file (`lockhtml/gui/index.html`). It works offline
and needs no server:

- **Lock tab** — drop in one or more HTML files, set a PIN, toggle one-time view, download.
- **Unlock / Verify tab** — open a locked file with its PIN to preview and recover it.

Because it is plain HTML + Web Crypto, it runs identically in Chrome, Edge, Firefox,
Safari and on Windows, Linux, macOS, Android and iOS.

## 📸 Screenshots

<div align="center">

**The GUI — lock any file straight from your browser**

<img src="assets/gui-lock.png" alt="LockHTML GUI - lock tab" width="780">

<br><br>

**A locked file asks for the PIN before revealing anything**

<img src="assets/gate.png" alt="LockHTML unlock gate" width="520">

</div>

## 🔬 How it works

1. Your document is encrypted with **AES-256-GCM**.
2. The key is derived from your PIN with **PBKDF2-SHA256** and a random 16-byte salt.
3. The salt, IV and ciphertext are embedded as JSON inside a small *viewer* page.
4. Opening the file runs the viewer, which asks for the PIN and decrypts **in the browser**
   using the Web Crypto API. The plaintext never leaves the device.

```
locked.html = viewer shell  +  { salt, iv, AES-256-GCM(ciphertext), one-time flag }
```

The CLI (Python) and the GUI (JavaScript) implement the same format, so files lock and
unlock interchangeably across both. See [`lockhtml/core.py`](lockhtml/core.py) for the spec.

## 🛡️ Security model — read this

**The PIN gives you real encryption.** Without it, the file is unreadable even if someone
opens it in a text editor and inspects the source. Wrong PINs are rejected cryptographically
(AES-GCM authentication), not by a simple string check.

**"One-time view" is a browser-enforced deterrent, not a server guarantee.** Since the file
has no server, expiry is stored in the browser's `localStorage`. A determined recipient can
copy the file first, open it in another browser or incognito window, clear their storage, or
screenshot the decrypted page. It stops casual re-sharing and accidental forwarding; it is not
a hard guarantee.

**This is not a substitute for end-to-end tools** when the stakes are high (medical records,
credentials, legal documents). Once a recipient decrypts, the content is on their screen and
in their memory. For genuinely enforced single-view delivery, use a server that deletes the
document after the first fetch.

| Property | Guarantee |
| --- | --- |
| Content unreadable without PIN | ✅ Strong (AES-256-GCM) |
| Wrong PIN rejected | ✅ Strong (authenticated encryption) |
| Works offline / no upload | ✅ Yes |
| Truly view-once | ⚠️ Best-effort (client-side) |
| Survives a determined recipient | ❌ No |

## 📂 Project layout

```
lockhtml/
├── lockhtml/
│   ├── core.py              # crypto + payload format
│   ├── cli.py               # command-line interface
│   ├── templates/
│   │   └── viewer.html      # the unlock shell embedded in every locked file
│   └── gui/
│       ├── app.html         # GUI source (template placeholder)
│       └── index.html       # generated, self-contained GUI
├── tools/build_gui.py       # inlines viewer.html into the GUI
├── tests/test_core.py       # crypto + CLI tests
├── examples/                # sample.html and its locked twin
└── .github/workflows/       # CI + GitHub Pages deploy
```

## 🤝 Contributing

Issues and pull requests are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

```bash
git clone https://github.com/drsamonline/lockhtml
cd lockhtml
pip install -e ".[dev]"
make test        # run the test suite
make gui         # regenerate lockhtml/gui/index.html
```

## 📜 License

[MIT](LICENSE) © Dr Sohil Momin

<div align="center"><sub>Built for the web. Runs on any OS. Nothing leaves your device.</sub></div>
