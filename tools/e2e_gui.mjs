// Locks files using the GUI's own JavaScript code path (embedded + streaming)
// and writes them out so the Python core can verify cross-implementation
// compatibility. Run tools/e2e_gui_verify.py afterwards.
//
//   node tools/e2e_gui.mjs /tmp/lockhtml-gui
//
// Set CHROME to the browser binary if puppeteer-core cannot find one.

import fs from "fs";
import path from "path";
import puppeteer from "puppeteer-core";

const DIR = process.argv[2] || "/tmp/lockhtml-gui";
fs.mkdirSync(DIR, { recursive: true });

const browser = await puppeteer.launch({
  executablePath: process.env.CHROME || undefined,
  headless: "new",
  args: ["--no-sandbox", "--disable-setuid-sandbox", "--allow-file-access-from-files"],
});
const page = await browser.newPage();
const errors = [];
page.on("pageerror", (e) => errors.push(e.message));
await page.goto("file://" + path.resolve("lockhtml/gui/index.html"), { waitUntil: "load" });
await new Promise((r) => setTimeout(r, 500));

const out = await page.evaluate(async () => {
  const doc = new TextEncoder().encode("<!DOCTYPE html><html><body><p>ORION-7742 GUI</p></body></html>");
  const kf = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
  const base = { pin: "4821", oneTime: false, maxViews: null, notBefore: null, expires: null,
                 watermark: "GUI-WM", decoyPin: null, kind: "html", name: null };
  const files = {};
  const embedded = async (tag, extra) => {
    const p = await makePayload(doc, { ...base, ...extra });
    files[tag + ".html"] = VIEWER_TEMPLATE_ARGON2.replace("__PAYLOAD__", JSON.stringify(p));
  };
  await embedded("gui_argon2", { kdf: "argon2id", keyfile: null });
  const pbp = await makePayload(doc, { ...base, kdf: "pbkdf2", keyfile: null });
  files["gui_pbkdf2.html"] = VIEWER_TEMPLATE.replace("__PAYLOAD__", JSON.stringify(pbp));
  const pkf = await makePayload(doc, { ...base, kdf: "argon2id", keyfile: kf });
  files["gui_keyfile.html"] = VIEWER_TEMPLATE_ARGON2.replace("__PAYLOAD__", JSON.stringify(pkf));

  // streaming bundle
  const built = await streamEncrypt(doc, { ...base, kdf: "pbkdf2", keyfile: null,
    chunkSize: 65536, dataName: "gui_stream.bin" });
  files["gui_stream.html"] = VIEWER_TEMPLATE.replace("__PAYLOAD__", JSON.stringify(built.payload));
  const binBytes = new Uint8Array(await built.bin.arrayBuffer());
  let s = ""; for (let i = 0; i < binBytes.length; i++) s += String.fromCharCode(binBytes[i]);
  files["gui_stream.bin.b64"] = btoa(s);
  files["gui_kf.b64"] = btoa(String.fromCharCode(...kf));
  return files;
});

for (const [name, content] of Object.entries(out)) {
  fs.writeFileSync(path.join(DIR, name), content);
}
console.log("page errors:", errors.length ? errors : "none");
console.log("wrote", Object.keys(out).length, "files to", DIR);
await browser.close();
