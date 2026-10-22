// check.js parses each script it is given as a browser at the floor does, a classic script of
// ES2020 at most, with the acorn release vendored beside it (#617). It reads [{path, source}] as
// JSON on stdin and writes [{path, detail}] as JSON on stdout, one entry per script refused: past
// the cap when acorn's latest JavaScript parses the script, and not parsing when that refuses it
// too, as it does module syntax and every early error.
"use strict";

const fs = require("fs");
const acorn = require("./acorn.js");

const scripts = JSON.parse(fs.readFileSync(0, "utf8"));
const refused = [];
for (const script of scripts) {
  try {
    acorn.parse(script.source, { ecmaVersion: 2020, sourceType: "script", allowHashBang: false });
  } catch (capped) {
    let later = true;
    try {
      acorn.parse(script.source, { ecmaVersion: "latest", sourceType: "script" });
    } catch {
      later = false;
    }
    refused.push({
      path: script.path,
      detail: (later ? "syntax newer than ES2020, the cap: " : "does not parse: ") + capped.message,
    });
  }
}
process.stdout.write(JSON.stringify(refused));
