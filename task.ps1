param(
  [ValidateSet("check","test","run")]
  [string]$Task = "check"
)

$ErrorActionPreference = "Stop"

function Run-Cmd($cmd) {
  Write-Host ">> $cmd"
  iex $cmd
}

if ($Task -eq "run") {
  Run-Cmd "python -m invariants.cli -c invariants.yml"
  exit 0
}

if ($Task -eq "test") {
  Run-Cmd "pytest -q"
  exit 0
}

# check: full gate
Run-Cmd "python -m compileall app invariants"
Run-Cmd "pytest -q"
Run-Cmd "python -m invariants.cli -c invariants.yml"
Write-Host " OK"
