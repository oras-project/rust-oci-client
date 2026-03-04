const fs = require("fs");

const cargo = fs
  .readFileSync("../../Cargo.toml", "utf8")
  .match(/^version = "(.+)"/m)?.[1];

if (!cargo) {
  console.error("Could not read version from Cargo.toml");
  process.exit(1);
}

const pkgPath = "package.json";
const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));

if (pkg.version !== cargo) {
  pkg.version = cargo;
  fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + "\n");
  console.log("Synced package.json version to", cargo);
} else {
  console.log("Versions already in sync:", cargo);
}
