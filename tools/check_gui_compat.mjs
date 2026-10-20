// Verifies the generated GUI is self-consistent and format-compatible.
//
//   1. Extracts the viewer template that the browser would parse from
//      lockhtml/gui/index.html.
//   2. Locks a sample document using the same Web Crypto code path the GUI uses.
//   3. Round-trips it inside Node.
//   4. Writes the locked file to disk so a second step (the Python CLI) can
//      confirm cross-implementation compatibility.
//
// Usage: node tools/check_gui_compat.mjs [outfile]

import fs from "fs";

const GUI = "lockhtml/gui/index.html";
const OUT = process.argv[2] || "/tmp/gui_locked.html";
const DOC = "<!DOCTYPE html><html><body><h1>From GUI</h1><p>ORION-7742</p></body></html>";
const PIN = "4821";

const html = fs.readFileSync(GUI, "utf8");
// The minifier may switch quote style, so accept either and evaluate the literal.
const m = html.match(/\bVIEWER_TEMPLATE\s*=\s*('(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")/);
if (!m) throw new Error("VIEWER_TEMPLATE not found in " + GUI);
const VIEWER_TEMPLATE = Function("return " + m[1])();
if (!VIEWER_TEMPLATE.includes("__PAYLOAD__")) throw new Error("template missing __PAYLOAD__");
console.log("viewer template extracted   : OK");

const enc = new TextEncoder();
const dec = new TextDecoder();
const b64 = (b) => Buffer.from(b).toString("base64");
const unb64 = (s) => new Uint8Array(Buffer.from(s, "base64"));

async function deriveKey(pin, salt, iterations, usage) {
  const base = await crypto.subtle.importKey("raw", enc.encode(pin), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    base, { name: "AES-GCM", length: 256 }, false, usage);
}

const salt = crypto.getRandomValues(new Uint8Array(16));
const iv = crypto.getRandomValues(new Uint8Array(12));
const key = await deriveKey(PIN, salt, 250000, ["encrypt", "decrypt"]);
const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(DOC)));
const id = Buffer.from(new Uint8Array(await crypto.subtle.digest("SHA-256", ct)).slice(0, 8)).toString("hex");

const payload = { v: 2, kind: "html", name: null, kdf: "pbkdf2", kdfparams: { iter: 250000 },
  salt: b64(salt), iv: b64(iv), ct: b64(ct), id, onetime: false, maxviews: null,
  notbefore: null, expires: null, watermark: null, keyfile: false, sig: null, decoy: null };
const locked = VIEWER_TEMPLATE.replace("__PAYLOAD__", JSON.stringify(payload));

if (locked.includes("ORION-7742")) throw new Error("plaintext leaked into locked file");
console.log("plaintext leak check        : OK");

// round-trip inside Node
const key2 = await deriveKey(PIN, unb64(payload.salt), payload.kdfparams.iter, ["decrypt"]);
const back = dec.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(payload.iv) }, key2, unb64(payload.ct)));
if (back !== DOC) throw new Error("round-trip mismatch");
console.log("Web Crypto round-trip       : OK");

fs.writeFileSync(OUT, locked);
console.log("wrote                       : " + OUT + " (" + locked.length + " bytes)");
