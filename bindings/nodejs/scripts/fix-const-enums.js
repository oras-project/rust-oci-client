const fs = require("fs");

const file = "index.d.ts";

if (!fs.existsSync(file)) {
  console.log("No index.d.ts to fix (not yet generated)");
  process.exit(0);
}

const content = fs.readFileSync(file, "utf8");
const fixed = content.replace(/export declare const enum/g, "export enum");

if (content !== fixed) {
  fs.writeFileSync(file, fixed);
  console.log("Fixed const enum declarations in", file);
} else {
  console.log("No const enum declarations to fix in", file);
}
