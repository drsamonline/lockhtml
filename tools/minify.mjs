// Minify the generated LockHTML assets.
//
//   node tools/minify.mjs
//
// Minifies lockhtml/gui/index.html and the two viewer templates in place.
// The viewer templates are embedded into every locked file, so shrinking them
// shrinks the output. Verification (tests + the browser end-to-end check) runs
// afterwards and will catch any minification that broke behaviour.

import fs from "fs";
import { minify } from "html-minifier-terser";

const FILES = [
  "lockhtml/gui/index.html",
  "lockhtml/templates/viewer.html",
  "lockhtml/templates/viewer-argon2.html",
];

const OPTS = {
  collapseWhitespace: true,
  conservativeCollapse: true,
  removeComments: true,
  removeRedundantAttributes: true,
  minifyCSS: true,
  minifyJS: { compress: { passes: 2 }, mangle: true },
  keepClosingSlash: true,
  caseSensitive: true,
};

let totalBefore = 0, totalAfter = 0;
for (const file of FILES) {
  const before = fs.readFileSync(file, "utf8");
  const after = await minify(before, OPTS);
  if (!after.includes("__PAYLOAD__")) {
    throw new Error(`minification dropped the __PAYLOAD__ placeholder in ${file}`);
  }
  fs.writeFileSync(file, after);
  totalBefore += Buffer.byteLength(before);
  totalAfter += Buffer.byteLength(after);
  const pct = (100 * (1 - Buffer.byteLength(after) / Buffer.byteLength(before))).toFixed(1);
  console.log(`${file}: ${Buffer.byteLength(before).toLocaleString()} -> ${Buffer.byteLength(after).toLocaleString()} bytes (-${pct}%)`);
}
console.log(`total: ${totalBefore.toLocaleString()} -> ${totalAfter.toLocaleString()} bytes`);
