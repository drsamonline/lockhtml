// End-to-end browser test: opens files locked by the Python CLI in a real
// headless Chrome and checks every behaviour, for both the embedded and the
// streaming container.
//
//   python tools/e2e_fixtures.py /tmp/lockhtml-e2e
//   CHROME=/path/to/chrome node tools/e2e_browser.mjs /tmp/lockhtml-e2e
//
// Set CHROME to the browser binary; defaults to whatever puppeteer-core finds.

import fs from "fs";
import path from "path";
import puppeteer from "puppeteer-core";

const DIR = process.argv[2] || "/tmp/lockhtml-e2e";
const file = (n) => "file://" + path.join(DIR, n);
const at = (n) => path.join(DIR, n);

const browser = await puppeteer.launch({
  executablePath: process.env.CHROME || undefined,
  headless: "new",
  args: ["--no-sandbox", "--disable-setuid-sandbox", "--allow-file-access-from-files"],
});
const results = [];
const ok = (name, cond) => { results.push([name, cond]); console.log((cond ? "PASS " : "FAIL ") + name); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const page = await browser.newPage();
await page.setViewport({ width: 900, height: 700 });
page.on("pageerror", (e) => console.log("  [pageerror]", e.message));

const open = (f) => page.goto(file(f), { waitUntil: "load" });
const type = async (pin) => { await page.type("#pin", pin); await page.click("#unlock"); };
async function waitStage() {
  try {
    await page.waitForFunction(() => !document.getElementById("stage").classList.contains("hidden"), { timeout: 25000 });
    return true;
  } catch { return false; }
}
const vis = (id) => page.evaluate((x) => !document.getElementById(x).classList.contains("hidden"), id);
const text = (s) => page.evaluate((x) => (document.querySelector(x) || {}).textContent || "", s);
const srcdoc = () => page.evaluate(() => document.getElementById("viewer").srcdoc || "");
const upload = async (sel, f) => (await page.$(sel)).uploadFile(at(f));

// ---- embedded container ----
await open("a_argon2.html"); await type("4821");
ok("embedded: Argon2id unlock", (await waitStage()) && (await srcdoc()).includes("ORION-7742"));

await open("b_pbkdf2.html"); await type("4821");
ok("embedded: PBKDF2 unlock", (await waitStage()) && (await srcdoc()).includes("ORION-7742"));

await open("c_keyfile.html"); await upload("#keyfile", "kf.bin"); await type("4821");
ok("embedded: keyfile unlock", (await waitStage()) && (await srcdoc()).includes("ORION-7742"));
await open("c_keyfile.html"); await type("4821");
ok("embedded: missing keyfile rejected", !(await waitStage()));

await open("e_signed.html"); await type("4821"); await waitStage();
ok("embedded: Ed25519 verified", (await text("#msg")).toLowerCase().includes("verified"));

await open("f_watermark.html"); await type("4821"); await waitStage();
ok("embedded: watermark shown", (await vis("wm")) && (await text("#wmText")) === "CONFIDENTIAL");

await open("g_file.html"); await type("4821"); await waitStage();
ok("embedded: binary -> download view", await vis("dlwrap"));

await open("h_decoy.html"); await type("duress"); await waitStage();
ok("embedded: decoy PIN opens decoy", (await srcdoc()).includes("No content"));
await open("h_decoy.html"); await type("realpin"); await waitStage();
ok("embedded: real PIN opens real doc", (await srcdoc()).includes("ORION-7742"));

await open("d_maxviews.html"); await type("4821"); await waitStage();
await open("d_maxviews.html"); await type("4821"); await waitStage();
await open("d_maxviews.html"); await sleep(1000);
ok("embedded: max-views expiry", await page.evaluate(() => document.getElementById("pin").classList.contains("hidden")));

// ---- streaming container ----
await open("s_html.html"); await upload("#datafile", "s_html.bin"); await type("4821");
ok("stream: html renders", (await waitStage()) && (await srcdoc()).includes("ORION-7742"));

await open("s_big.html"); await upload("#datafile", "s_big.bin"); await type("4821");
ok("stream: 2 MB / 8 chunks -> download", (await waitStage()) && (await vis("dlwrap")));

await open("s_argon2.html"); await upload("#datafile", "s_argon2.bin"); await type("4821");
ok("stream: Argon2id", (await waitStage()) && (await vis("dlwrap")));

await open("s_keyfile.html"); await upload("#keyfile", "kf.bin"); await upload("#datafile", "s_keyfile.bin"); await type("4821");
ok("stream: keyfile", (await waitStage()) && (await vis("dlwrap")));
await open("s_keyfile.html"); await upload("#datafile", "s_keyfile.bin"); await type("4821");
ok("stream: missing keyfile rejected", !(await waitStage()));

await open("s_signed.html"); await upload("#datafile", "s_signed.bin"); await type("4821"); await waitStage();
ok("stream: signature verified", (await text("#msg")).toLowerCase().includes("verified"));

await open("s_html.html"); await upload("#datafile", "s_html_tampered.bin"); await type("4821");
ok("stream: tampered sidecar rejected", !(await waitStage()));

await open("s_html.html"); await type("4821");
ok("stream: missing data file rejected", !(await waitStage()));

await browser.close();
const failed = results.filter((r) => !r[1]).length;
console.log(`\n${results.length - failed}/${results.length} browser checks passed`);
process.exit(failed ? 1 : 0);
