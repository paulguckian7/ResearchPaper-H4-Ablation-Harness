<#
.SYNOPSIS
    Runs every H4 configuration's confirmatory ablation, piping "EXECUTE"
    into each runner's confirmation prompt automatically.

.STATUS (as of this rewrite)
    All 15 configurations have been executed for real on Docker at least
    once and passed. Ten real bugs were found and fixed getting here --
    see each config's manifest "status" field and the harness README for
    specifics. None were in the underlying claims about Interface,
    Execution Pathway or Authority; all were in the scaffolding measuring
    them (evidence coupling, polarity inversion, readiness races, a
    nonexistent Docker tag, root-vs-non-root identity, a commodity
    tool's internal behaviour not matching an initial assumption about
    it). There is no more "unverified" tier -- an earlier version of
    this script excluded I-2, X-2 and A-4 by default because they
    genuinely had never been run; that is no longer true, so that
    distinction is removed here.

.WHAT THIS DOES AND DOES NOT DO
    - Pipes the literal string "EXECUTE" into each runner's stdin, which
      satisfies the `input("Type EXECUTE to continue: ")` prompt exactly
      as if you'd typed it. The prompt itself is NOT removed or bypassed
      -- this script just answers it the same way every time.
    - Runs --dry-run first for every config, and only proceeds to
      --execute if the dry-run succeeds. If dry-run fails, that config
      is skipped and flagged, not silently retried.
    - Runs BOTH --level system and --level system-of-systems for I-1,
      X-1, A-1, A-2, A-3, A-5 (same technical mechanism, different
      governance label -- see each manifest's note on this). Runs only
      --level system for everything else (A-6, every C-config, and
      I-2/X-2/A-4, none of which have a second level built).
    - Continues past a FAIL/AMBIGUOUS outcome by default (these are
      independent experiments; one failing doesn't invalidate the
      others) but prints it prominently and includes it in the final
      summary. Pass -StopOnFailure to abort the whole batch at the
      first non-PASS instead.
    - Writes full stdout/stderr for every run to logs\<ID>_<level>.log,
      so nothing is lost even though the console only shows a summary.
    - Numbers of existing runs are respected -- if a config already has
      run-01/run-02 from earlier manual testing, this continues from
      run-03, it does not overwrite or duplicate.

.A NOTE ON A-4's RUNTIME
    A-4 tears down and rebuilds its container between every run
    (docker compose down -v), which means the multi-minute signature
    download and clamd startup wait happens fresh for EACH of the 5
    runs, not once for the batch. This is expected, not a hang -- budget
    real time for it.

.USAGE
    cd C:\Research\H4_Ablation_Harness
    .\Run-All-H4.ps1

    Options:
    .\Run-All-H4.ps1 -Runs 5 -StopOnFailure
    .\Run-All-H4.ps1 -Only A-3,A-5,A-6,C-1,C-2,C-3   # just the Authority/Cut priority set
    .\Run-All-H4.ps1 -Only A-4                       # just the slow one, on its own
#>

param(
    [int]$Runs = 5,
    [switch]$StopOnFailure,
    [string[]]$Only = @()
)

$ErrorActionPreference = "Stop"
$RepoRoot = Get-Location

# Bug fixed here, twice. A native program (python.exe) writing to
# stderr -- which a real crash does, via its traceback -- gets promoted
# to a PowerShell-level TERMINATING error under $ErrorActionPreference
# = "Stop". That meant a real Python crash aborted this script BEFORE
# the Out-File line that logs the output ever ran, so the log for that
# config was never created. Confirmed twice on real batch runs: once
# on PowerShell 7 (X-1 crashed, log missing), and again after a first
# fix that only covered PowerShell 7.3+'s
# $PSNativeCommandUseErrorActionPreference setting -- which does not
# exist on Windows PowerShell 5.1, the engine actually in use here (the
# console banner reads "Windows PowerShell", not "PowerShell 7"). The
# underlying stderr-becomes-terminating-error behaviour is present on
# every PowerShell version via an older mechanism, not just 7.3+, so a
# version-gated fix targeting only the newer setting left 5.1
# unprotected. Fixed properly this time with a helper that runs a
# native command under a LOCALLY relaxed error preference, restored
# immediately afterward, which works identically on every PowerShell
# version rather than depending on a version-specific setting.
function Invoke-Native {
    param([string]$Exe, [string[]]$ArgList, [string]$StdinText = $null)
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        if ($StdinText) {
            $out = $StdinText | & $Exe @ArgList 2>&1
        } else {
            $out = & $Exe @ArgList 2>&1
        }
        return @{ Output = $out; ExitCode = $LASTEXITCODE }
    } finally {
        $ErrorActionPreference = $prev
    }
}

# Config -> (runner script, levels to run). All 15 configurations,
# all confirmed on real Docker as of this rewrite.
$all = [ordered]@{
    "A-3"  = @{ runner = "run_a3.py";  levels = @("system", "system-of-systems") }
    "A-5"  = @{ runner = "run_a5.py";  levels = @("system", "system-of-systems") }
    "A-6"  = @{ runner = "run_a6.py";  levels = @("system") }
    "C-1"  = @{ runner = "run_c1.py";  levels = @("system") }
    "C-2"  = @{ runner = "run_c2.py";  levels = @("system") }
    "C-3"  = @{ runner = "run_c3.py";  levels = @("system") }
    "A-1"  = @{ runner = "run_a1.py";  levels = @("system", "system-of-systems") }
    "A-2"  = @{ runner = "run_a2.py";  levels = @("system", "system-of-systems") }
    "X-1"  = @{ runner = "run_x1.py";  levels = @("system", "system-of-systems") }
    "C-4a" = @{ runner = "run_c4a.py"; levels = @("system") }
    "C-4b" = @{ runner = "run_c4b.py"; levels = @("system") }
    "C-4c" = @{ runner = "run_c4c.py"; levels = @("system") }
    "I-2"  = @{ runner = "run_i2.py";  levels = @("system") }
    "X-2"  = @{ runner = "run_x2.py";  levels = @("system") }
    "A-4"  = @{ runner = "run_a4.py";  levels = @("system") }
}

$toRun = $all
if ($Only.Count -gt 0) {
    $filtered = [ordered]@{}
    foreach ($k in $Only) {
        if ($toRun.Contains($k)) { $filtered[$k] = $toRun[$k] }
        else { Write-Warning "Requested '$k' is not a known configuration (check spelling)." }
    }
    $toRun = $filtered
}

$logDir = Join-Path $RepoRoot "logs"
New-Item -ItemType Directory -Path $logDir -Force | Out-Null

$results = @()

Write-Host ""
Write-Host "=== Plan ===" -ForegroundColor Cyan
foreach ($id in $toRun.Keys) {
    $levelsStr = $toRun[$id].levels -join ", "
    Write-Host "  $id  ->  $($toRun[$id].runner)  [$levelsStr]  x$Runs runs each"
}
if ($toRun.Contains("A-4")) {
    Write-Host ""
    Write-Host "  Note: A-4 rebuilds and re-downloads signatures on every run -- expect this one to dominate total time." -ForegroundColor Yellow
}
Write-Host ""

foreach ($id in $toRun.Keys) {
    $cfg = $toRun[$id]
    $expDir = Join-Path $RepoRoot "experiments\$id"
    if (-not (Test-Path $expDir)) {
        Write-Warning "Skipping $id -- experiments\$id not found."
        $results += [pscustomobject]@{ Id = $id; Level = "-"; Outcome = "SKIPPED (dir missing)" }
        continue
    }

    Push-Location $expDir
    try {
        Write-Host "--- $id : dry-run ---" -ForegroundColor Cyan
        $dryLog = Join-Path $logDir "$($id)_dryrun.log"
        # Log FIRST, before anything else can throw and skip it.
        $dryResult = Invoke-Native -Exe "python" -ArgList @($cfg.runner, "--dry-run")
        $dryOutput = $dryResult.Output
        $dryExit = $dryResult.ExitCode
        $dryOutput | Out-File -FilePath $dryLog -Encoding utf8
        if ($dryExit -ne 0) {
            Write-Host "  DRY RUN FAILED (exit $dryExit) -- see $dryLog" -ForegroundColor Red
            $results += [pscustomobject]@{ Id = $id; Level = "-"; Outcome = "DRY-RUN FAILED" }
            if ($StopOnFailure) { throw "Stopping: dry-run failed for $id" }
            continue
        }
        Write-Host "  dry-run OK"

        foreach ($level in $cfg.levels) {
            Write-Host "--- $id : --level $level, --runs $Runs ---" -ForegroundColor Cyan
            $runLog = Join-Path $logDir "$($id)_$($level).log"

            # Same fix: log the output BEFORE checking exit code or
            # doing anything else that could throw, so a real crash is
            # always captured on disk, not just shown (and possibly
            # truncated/mangled) in the console.
            $runResult = Invoke-Native -Exe "python" -ArgList @($cfg.runner, "--execute", "--runs", $Runs, "--level", $level) -StdinText "EXECUTE"
            $output = $runResult.Output
            $runExit = $runResult.ExitCode
            $output | Out-File -FilePath $runLog -Encoding utf8

            $summaryLine = $output | Select-String -Pattern "^Summary:" | Select-Object -Last 1
            $passLine = $output | Select-String -Pattern "=> PASS" | Measure-Object
            $failLine = $output | Select-String -Pattern "=> FAIL" | Measure-Object
            $ambigLine = $output | Select-String -Pattern "AMBIGUOUS" | Measure-Object

            if ($runExit -ne 0) {
                Write-Host "  RUNNER EXITED WITH ERROR (exit $runExit) -- see $runLog" -ForegroundColor Red
                $outcome = "ERROR"
            } elseif ($failLine.Count -gt 0 -or $ambigLine.Count -gt 0) {
                Write-Host "  $($passLine.Count) pass, $($failLine.Count) fail, $($ambigLine.Count) ambiguous -- see $runLog" -ForegroundColor Yellow
                $outcome = "NEEDS REVIEW ($($passLine.Count) pass / $($failLine.Count) fail / $($ambigLine.Count) ambiguous)"
            } else {
                Write-Host "  $($passLine.Count)/$Runs PASS" -ForegroundColor Green
                $outcome = "PASS ($($passLine.Count)/$Runs)"
            }

            $results += [pscustomobject]@{ Id = $id; Level = $level; Outcome = $outcome }

            if ($runExit -ne 0 -and $StopOnFailure) {
                throw "Stopping: $id --level $level exited with an error"
            }
            if ($failLine.Count -gt 0 -and $StopOnFailure) {
                throw "Stopping: $id --level $level reported a FAIL"
            }
        }
    } finally {
        Pop-Location
    }
}

Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Cyan
$results | Format-Table -AutoSize

$needsReview = $results | Where-Object { $_.Outcome -notlike "PASS*" -and $_.Outcome -notlike "SKIPPED*" }
if ($needsReview.Count -gt 0) {
    Write-Host ""
    Write-Host "$($needsReview.Count) result(s) need review:" -ForegroundColor Yellow
    $needsReview | ForEach-Object { Write-Host "  $($_.Id) [$($_.Level)]: $($_.Outcome)" -ForegroundColor Yellow }
    Write-Host "Check the corresponding files in .\logs\ before treating any of these as confirmatory." -ForegroundColor Yellow
} else {
    Write-Host ""
    Write-Host "All runs reported PASS. Logs are in .\logs\ for the record." -ForegroundColor Green
}

Write-Host ""
Write-Host "Next: zip each experiment's results\ folder and send them back for verification against the committed source hashes." -ForegroundColor Cyan
