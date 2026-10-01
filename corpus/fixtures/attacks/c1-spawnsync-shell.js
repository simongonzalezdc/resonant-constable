// F-SHELL-002 — synthetic attack fixture, class C1-SHELL-INTERP (CWE-78).
// The command arrives as one string and is handed to a shell: shell-string
// construction. Expected label: detect (R1-SHELL-STRING-EXEC).
const { spawnSync } = require("node:child_process");

function runContract(cmd) {
  return spawnSync(cmd, { shell: true });
}
