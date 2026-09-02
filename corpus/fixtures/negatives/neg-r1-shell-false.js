// N-SHELL-002 — typed negative for R1-SHELL-STRING-EXEC (class C1-SHELL-INTERP).
// Benign lookalike: argv in, shell:false. Expected label: pass.
const { spawnSync } = require("node:child_process");

function runArgv(argv) {
  return spawnSync(argv[0], argv.slice(1), { shell: false });
}
