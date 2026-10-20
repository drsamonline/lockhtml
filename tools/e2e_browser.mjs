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

const launch = () => puppeteer.launch({
  executablePath: process.env.CHROME || undefined,
  headless: "new",
  args: ["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage",
         "--disable-gpu", "--allow-file-access-from-files"],
});
let browser = await launch();
const results = [];
let sinceRecycle = 0;
const T0 = Date.now();
const ok = (name, cond) => {
  results.push([name, cond]);
  sinceRecycle++;
  console.log((cond ? "PASS " : "FAIL ") + name + "  +" + ((Date.now() - T0) / 1000).toFixed(1) + "s");
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let page;
async function freshPage() {
  // The sandbox is memory-tight, so Chrome can die part-way through a long run.
  // Relaunch it rather than losing the whole suite.
  if (!browser.connected) {
    try { await browser.close(); } catch { /* already gone */ }
    console.log("  [browser] relaunching");
    browser = await launch();
  }
  if (page) { try { await page.close(); } catch { /* already gone */ } }
  page = await browser.newPage();
  await page.setViewport({ width: 900, height: 700 });
  page.on("pageerror", (e) => console.log("  [pageerror]", e.message));
  page.on("error", (e) => console.log("  [crash]", e.message));
}
await freshPage();

// A long run of heavy decrypts can exhaust the renderer; if the frame detaches,
// start a clean page and carry on rather than failing the whole suite.
const RECYCLE_EVERY = 4;
const open = async (f) => {
  // Each viewer page keeps Argon2 WASM + decrypted buffers alive; recycle the
  // page regularly so a long run cannot exhaust the renderer.
  if (sinceRecycle >= RECYCLE_EVERY) { sinceRecycle = 0; await freshPage(); }
  for (let attempt = 0; ; attempt++) {
    try {
      return await page.goto(file(f), { waitUntil: "load" });
    } catch (e) {
      if (attempt >= 2) throw e;
      console.log("  [retry] navigation:", String(e.message).split("\n")[0]);
      await sleep(300);
      await freshPage();
    }
  }
};
const type = async (pin) => { await page.type("#pin", pin); await page.click("#unlock"); };
async function waitStage() {
  try {
    await page.waitForFunction(() => !document.getElementById("stage").classList.contains("hidden"), { timeout: 25000 });
    return true;
  } catch { return false; }
}
// For checks that expect a REJECTION: resolve as soon as either the stage opens
// (the check fails) or the viewer shows an error (the check passes). Waiting the
// full stage timeout for every negative case made the suite needlessly slow.
async function waitRejected(ms = 10000) {
  try {
    await page.waitForFunction(() => {
      const open = !document.getElementById("stage").classList.contains("hidden");
      const errored = document.getElementById("msg").classList.contains("err");
      return open || errored;
    }, { timeout: ms });
  } catch { /* nothing happened; treat as rejected */ }
  return page.evaluate(() => document.getElementById("stage").classList.contains("hidden"));
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
ok("embedded: missing keyfile rejected", await waitRejected());

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
ok("stream: missing keyfile rejected", await waitRejected());

await open("s_signed.html"); await upload("#datafile", "s_signed.bin"); await type("4821"); await waitStage();
ok("stream: signature verified", (await text("#msg")).toLowerCase().includes("verified"));

await open("s_html.html"); await upload("#datafile", "s_html_tampered.bin"); await type("4821");
ok("stream: tampered sidecar rejected", await waitRejected());

await open("s_html.html"); await type("4821");
ok("stream: missing data file rejected", await waitRejected());

// ---- X25519 recipient mode ----
await open("r_embedded.html"); await upload("#privkey", "rec.pem"); await page.click("#unlock");
ok("recipient: unlock with private key (no PIN)", (await waitStage()) && (await srcdoc()).includes("ORION-7742"));

await open("r_embedded.html"); await page.click("#unlock");
ok("recipient: missing private key rejected", await waitRejected());

await open("r_embedded.html"); await upload("#privkey", "other.pem"); await page.click("#unlock");
ok("recipient: wrong private key rejected", await waitRejected());

await open("r_pin.html"); await upload("#privkey", "rec.pem"); await type("4821");
ok("recipient: private key + PIN", (await waitStage()) && (await srcdoc()).includes("ORION-7742"));

await open("r_pin.html"); await upload("#privkey", "rec.pem"); await page.click("#unlock");
ok("recipient: PIN required but missing", await waitRejected());

await open("r_file.html"); await upload("#privkey", "rec.pem"); await page.click("#unlock");
ok("recipient: binary -> download", (await waitStage()) && (await vis("dlwrap")));

await open("r_stream.html"); await upload("#privkey", "rec.pem"); await upload("#datafile", "r_stream.bin"); await page.click("#unlock");
ok("recipient: streaming bundle", (await waitStage()) && (await vis("dlwrap")));

// ---- Shamir shares mode ----
await open("sh_embedded.html"); await upload("#sharesFile", "sh_embedded.shares.txt"); await page.click("#unlock");
ok("shares: 3-of-5 opens via .shares.txt", (await waitStage()) && (await srcdoc()).includes("ORION-7742"));

await open("sh_embedded.html"); await upload("#sharesFile", "sh_two.txt"); await page.click("#unlock");
ok("shares: 2 of 3 rejected", await waitRejected());

await open("sh_embedded.html"); await page.click("#unlock");
ok("shares: none rejected", await waitRejected());

await open("sh_pin.html"); await upload("#sharesFile", "sh_pin.shares.txt"); await type("4821");
ok("shares: with PIN", (await waitStage()) && (await srcdoc()).includes("ORION-7742"));

await open("sh_stream.html"); await upload("#sharesFile", "sh_stream.shares.txt"); await upload("#datafile", "sh_stream.bin"); await page.click("#unlock");
ok("shares: streaming bundle", (await waitStage()) && (await vis("dlwrap")));

// ---- hidden volume + streaming decoy ----
await open("hidden.html"); await type("4821");
ok("hidden: cover PIN -> cover", (await waitStage()) && (await srcdoc()).includes("COVER-1111"));

await open("hidden.html"); await type("0000");
ok("hidden: hidden PIN -> real", (await waitStage()) && (await srcdoc()).includes("PISCES-9931"));

await open("hidden.html"); await type("9999");
ok("hidden: wrong PIN rejected", await waitRejected());

await open("hidden_stream.html"); await upload("#datafile", "hidden_stream.bin"); await type("4821");
ok("stream decoy: real PIN -> download", (await waitStage()) && (await vis("dlwrap")));

await open("hidden_stream.html"); await upload("#datafile", "hidden_stream.bin"); await type("0000");
ok("stream decoy: decoy PIN -> decoy page",
   (await waitStage()) && (await srcdoc()).includes("DECOY-PAGE") && !(await vis("dlwrap")));

await browser.close();
const failed = results.filter((r) => !r[1]).length;
console.log(`\n${results.length - failed}/${results.length} browser checks passed`);
process.exit(failed ? 1 : 0);
