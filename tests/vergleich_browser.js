#!/usr/bin/env node
// Prüft, dass die Browser-Fassung (tool/steckbrief-werkbank.html) für jede Datei
// eines Ordners Byte für Byte dasselbe liefert wie src/steckbrief.py.
// Aufruf:  node tests/vergleich_browser.js <ordner-mit-skripten>
// Führt nichts aus den Skripten aus, liest nur Bytes.
const fs = require("fs"), path = require("path"), { execFileSync } = require("child_process");
const wurzel = path.resolve(__dirname, "..");
const ordner = process.argv[2];
if (!ordner) { console.error("Aufruf: node tests/vergleich_browser.js <ordner>"); process.exit(2); }
const html = fs.readFileSync(path.join(wurzel, "tool/steckbrief-werkbank.html"), "utf8");
const kern = html.split("/*CORE-START*/")[1].split("/*CORE-END*/")[0];
const api = new Function(kern + ";return {buildSteckbrief,toMarkdown,toJson,llmText};")();
const ref = JSON.parse(execFileSync("python3", [path.join(__dirname, "_referenz.py"), ordner], { maxBuffer: 1 << 30 }).toString());
(async () => {
  let abweichungen = 0, n = 0;
  for (const [datei, soll] of Object.entries(ref)) {
    n++;
    const sb = await api.buildSteckbrief(path.basename(datei), new Uint8Array(fs.readFileSync(datei)), "x");
    for (const [art, fn] of [["json", api.toJson], ["md", api.toMarkdown], ["txt", api.llmText]]) {
      if (fn(sb) !== soll[art]) { abweichungen++; console.log("ABWEICHUNG (" + art + "): " + datei); break; }
    }
  }
  console.log(n + " Dateien, " + abweichungen + " Abweichungen");
  process.exit(abweichungen ? 1 : 0);
})();
