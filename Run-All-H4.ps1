<#
.SYNOPSIS
    Runs every VERIFIED H4 configuration's confirmatory ablation, piping
    "EXECUTE" into each runner's confirmation prompt automatically.

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
      --level system for A-6 and every C-config (governance is fixed in
      the container topology for these, not toggled by a flag).
    - Does NOT run I-2, X-2, or A-4 unless you pass -IncludeUnverified.
      These need mosquitto/nginx/ClamAV behaviour nobody has watched
      succeed yet -- read their manifests' known_risks before including
      them, and even then run them manually first, not in a blind batch.
    - Continues past a FAIL/AMBIGUOUS outcome by default (these are
      independent experiments; one failing doesn't invalidate the
      others) but prints it prominently and includes it in the final
      summary. Pass -StopOnFailure to abort the whole batch at the
      first non-PASS instead.
    - Writes full stdout/stderr for every run to logs\<ID>_<level>.log,
      so nothing is lost even though the console only shows a summary.

.USAGE
    cd C:\Research\H4_Ablation_Harness
    .\Run-All-H4.ps1

    Options:
    .\Run-All-H4.ps1 -Runs 5 -StopOnFailure
    .\Run-All-H4.ps1 -Only A-3,A-5,A-6,C-1,C-2,C-3   # just the Authority/Cut priority set
    .\Run-All-H4.ps1 -IncludeUnverified              # also attempts I-2, X-2, A-4
#>

param(
    [int]$Runs = 5,
    [switch]$StopOnFailure,
    [switch]$IncludeUnverified,
    [string[]]$Only = @()
)

$ErrorActionPreference = "Stop"
$RepoRoot = Get-Location

# Config -> (runner script, levels to run). Levels list has one entry
# per invocation; "system" and "system-of-systems" for the dual-level
# ones, just "system" for everything else.
$verified = [ordered]@{
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
}
$unverified = [ordered]@{
    "I-2" = @{ runner = "run_i2.py"; levels = @("system") }
    "X-2" = @{ runner = "run_x2.py"; levels = @("system") }
    "A-4" = @{ runner = "run_a4.py"; levels = @("system") }
}

$toRun = [ordered]@{}
foreach ($k in $verified.Keys) { $toRun[$k] = $verified[$k] }
if ($IncludeUnverified) {
    foreach ($k in $unverified.Keys) { $toRun[$k] = $unverified[$k] }
}
if ($Only.Count -gt 0) {
    $filtered = [ordered]@{}
    foreach ($k in $Only) {
        if ($toRun.Contains($k)) { $filtered[$k] = $toRun[$k] }
        else { Write-Warning "Requested '$k' is not in the runnable set (check spelling / -IncludeUnverified)." }
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
if (-not $IncludeUnverified) {
    Write-Host ""
    Write-Host "  (I-2, X-2, A-4 excluded -- pass -IncludeUnverified to attempt them)" -ForegroundColor Yellow
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
        $dryOutput = & python $cfg.runner --dry-run 2>&1
        $dryOutput | Out-File -FilePath $dryLog -Encoding utf8
        if ($LASTEXITCODE -ne 0) {
            Write-Host "  DRY RUN FAILED (exit $LASTEXITCODE) -- see $dryLog" -ForegroundColor Red
            $results += [pscustomobject]@{ Id = $id; Level = "-"; Outcome = "DRY-RUN FAILED" }
            if ($StopOnFailure) { throw "Stopping: dry-run failed for $id" }
            continue
        }
        Write-Host "  dry-run OK"

        foreach ($level in $cfg.levels) {
            Write-Host "--- $id : --level $level, --runs $Runs ---" -ForegroundColor Cyan
            $runLog = Join-Path $logDir "$($id)_$($level).log"

            $output = "EXECUTE" | & python $cfg.runner --execute --runs $Runs --level $level 2>&1
            $output | Out-File -FilePath $runLog -Encoding utf8

            $summaryLine = $output | Select-String -Pattern "^Summary:" | Select-Object -Last 1
            $passLine = $output | Select-String -Pattern "=> PASS" | Measure-Object
            $failLine = $output | Select-String -Pattern "=> FAIL" | Measure-Object
            $ambigLine = $output | Select-String -Pattern "AMBIGUOUS" | Measure-Object

            if ($LASTEXITCODE -ne 0) {
                Write-Host "  RUNNER EXITED WITH ERROR (exit $LASTEXITCODE) -- see $runLog" -ForegroundColor Red
                $outcome = "ERROR"
            } elseif ($failLine.Count -gt 0 -or $ambigLine.Count -gt 0) {
                Write-Host "  $($passLine.Count) pass, $($failLine.Count) fail, $($ambigLine.Count) ambiguous -- see $runLog" -ForegroundColor Yellow
                $outcome = "NEEDS REVIEW ($($passLine.Count) pass / $($failLine.Count) fail / $($ambigLine.Count) ambiguous)"
            } else {
                Write-Host "  $($passLine.Count)/$Runs PASS" -ForegroundColor Green
                $outcome = "PASS ($($passLine.Count)/$Runs)"
            }

            $results += [pscustomobject]@{ Id = $id; Level = $level; Outcome = $outcome }

            if ($LASTEXITCODE -ne 0 -and $StopOnFailure) {
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
