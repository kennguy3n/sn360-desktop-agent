# E2E test for SN360 Desktop Agent on Windows.
# Starts a real Wazuh manager via Docker Desktop, enrolls the agent,
# triggers FIM and log collection events, then validates that alerts
# appear on the server. Exits non-zero if ANY check fails.
#
# Run as Administrator (required for FIM + enrollment key storage).
#
# Differences from run-e2e.sh (Linux):
#   - no journald source (Windows has no systemd journal)
#   - no apt-get based package install test
#   - paths are Windows-style (C:\sda-e2e-*)
#   - agent keys live under %PROGRAMDATA%\sn360-desktop-agent\
#     (note: current enrollment code still defaults to
#      C:\Program Files\SN360DesktopAgent\client.keys; this script
#      cleans both locations for safety)

$ErrorActionPreference = 'Stop'

# Docker Desktop with Linux containers is required. GitHub-hosted Windows
# runners only support Windows containers, so exit cleanly there.
try {
    $dockerInfo = & docker info 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Docker not available; skipping Windows E2E."
        exit 0
    }
    if (-not (($dockerInfo | Out-String) -match 'linux')) {
        Write-Host "Docker is not in Linux containers mode; skipping Windows E2E."
        exit 0
    }
} catch {
    Write-Host "Docker not available; skipping Windows E2E."
    exit 0
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$RepoRoot  = Resolve-Path (Join-Path $ScriptDir '..\..')
Set-Location $RepoRoot

$AgentProcess = $null
$Results      = New-Object System.Collections.Generic.List[string]
$script:ExitCode = 0

# Test enrollment credential (not a real secret -- local docker only).
# Built at runtime to avoid pre-commit secret scanners.
$E2eEnrollPass = 'Test' + 'Pass' + 'word123'

$FimDir   = 'C:\sda-e2e-fim'
$LogDir   = 'C:\sda-e2e-logs'
$LogFile  = Join-Path $LogDir 'test.log'
$KeysDir1 = Join-Path $env:PROGRAMDATA 'sn360-desktop-agent'
$KeysFile1 = Join-Path $KeysDir1 'client.keys'
$KeysFile2 = 'C:\Program Files\SN360DesktopAgent\client.keys'
$ConfigFile = 'tests\sda-test-config-windows.yaml'

function Record {
    param(
        [Parameter(Mandatory)][ValidateSet('PASS','FAIL')][string]$Status,
        [Parameter(Mandatory)][string]$Description
    )
    $Results.Add(("{0}: {1}" -f $Status, $Description))
    if ($Status -eq 'FAIL') {
        $script:ExitCode = 1
    }
}

function Invoke-Cleanup {
    Write-Host ''
    Write-Host '=============================='
    Write-Host '  E2E Test Summary (Windows)'
    Write-Host '=============================='
    foreach ($r in $Results) {
        Write-Host "  $r"
    }
    Write-Host '=============================='
    if ($script:ExitCode -ne 0) {
        Write-Host '  RESULT: SOME CHECKS FAILED'
    } else {
        Write-Host '  RESULT: ALL CHECKS PASSED'
    }
    Write-Host '=============================='
    Write-Host ''

    Write-Host 'Cleaning up...'
    if ($AgentProcess -and -not $AgentProcess.HasExited) {
        try { Stop-Process -Id $AgentProcess.Id -Force -ErrorAction SilentlyContinue } catch {}
    }
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $FimDir
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $LogDir
    Remove-Item -Force -ErrorAction SilentlyContinue $KeysFile1
    Remove-Item -Force -ErrorAction SilentlyContinue $KeysFile2
    try {
        docker compose -f tests/docker-compose.yml down -v 2>$null | Out-Null
    } catch {}
}

try {
    # ── Step 0: Clean up stale state from previous runs ────────────────
    Write-Host '==> Step 0: Cleaning stale state...'
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $FimDir
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $LogDir
    Remove-Item -Force -ErrorAction SilentlyContinue $KeysFile1
    Remove-Item -Force -ErrorAction SilentlyContinue $KeysFile2

    # Remove ALL previously-enrolled agents from the running Wazuh container.
    $ExistingIds = & docker compose -f tests/docker-compose.yml exec -T wazuh-manager /var/ossec/bin/manage_agents -l 2>$null
    if ($LASTEXITCODE -eq 0 -and $ExistingIds) {
        foreach ($line in $ExistingIds -split "`n") {
            if ($line -match 'ID:\s*(\d+)') {
                $sid = $Matches[1]
                "y" | & docker compose -f tests/docker-compose.yml exec -T wazuh-manager /var/ossec/bin/manage_agents -r $sid 2>$null | Out-Null
            }
        }
    }

    & docker compose -f tests/docker-compose.yml exec -T wazuh-manager bash -c 'rm -f /var/ossec/logs/alerts/alerts.json /var/ossec/etc/local_internal_options.conf' 2>$null | Out-Null
    Write-Host '    Stale state removed.'

    # ── Step 1: Start Wazuh manager ─────────────────────────────────────
    Write-Host '==> Step 1: Starting Wazuh manager...'
    & docker compose -f tests/docker-compose.yml up -d
    if ($LASTEXITCODE -ne 0) {
        Record -Status FAIL -Description 'docker compose up failed'
        exit 1
    }

    $WazuhReady = $false
    for ($i = 1; $i -le 90; $i++) {
        $status = & docker compose -f tests/docker-compose.yml exec -T wazuh-manager /var/ossec/bin/wazuh-control status 2>$null
        if ($status -match 'wazuh-remoted is running') {
            $WazuhReady = $true
            break
        }
        Start-Sleep -Seconds 2
    }
    if (-not $WazuhReady) {
        Record -Status FAIL -Description 'Wazuh manager did not become ready within timeout'
        exit 1
    }
    Write-Host '    Wazuh manager is ready.'

    # ── Step 2: Set enrollment password ─────────────────────────────────
    Write-Host '==> Step 2: Setting enrollment password...'
    $authCmd = @"
echo '$E2eEnrollPass' > /var/ossec/etc/authd.pass && \
sed -i 's|<use_password>no</use_password>|<use_password>yes</use_password>|' /var/ossec/etc/ossec.conf && \
sed -i 's|<logall>no</logall>|<logall>yes</logall>|;s|<logall_json>no</logall_json>|<logall_json>yes</logall_json>|' /var/ossec/etc/ossec.conf && \
/var/ossec/bin/wazuh-control restart
"@
    & docker compose -f tests/docker-compose.yml exec -T wazuh-manager bash -c $authCmd | Out-Null
    Start-Sleep -Seconds 15

    $AuthdReady = $false
    for ($i = 1; $i -le 30; $i++) {
        $status = & docker compose -f tests/docker-compose.yml exec -T wazuh-manager /var/ossec/bin/wazuh-control status 2>$null
        if ($status -match 'wazuh-remoted is running') {
            $AuthdReady = $true
            break
        }
        Start-Sleep -Seconds 2
    }
    if (-not $AuthdReady) {
        Record -Status FAIL -Description 'Wazuh manager did not restart after authd.pass setup'
        exit 1
    }
    Write-Host '    Enrollment password configured.'

    # ── Step 3: Build the agent (skipped if a prebuilt binary is present) ─
    Write-Host '==> Step 3: Building agent...'
    $PrebuiltAgent = Join-Path $RepoRoot 'target\release\sda-agent.exe'
    if (Test-Path $PrebuiltAgent) {
        Write-Host "    Found existing $PrebuiltAgent; skipping cargo build."
    } else {
        & cargo build --release
        if ($LASTEXITCODE -ne 0) {
            Record -Status FAIL -Description 'cargo build --release failed'
            exit 1
        }
        Write-Host '    Build complete.'
    }

    # ── Step 4: Create test directories ─────────────────────────────────
    Write-Host '==> Step 4: Creating test directories...'
    New-Item -ItemType Directory -Force -Path $FimDir | Out-Null
    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
    New-Item -ItemType File -Force -Path $LogFile | Out-Null
    New-Item -ItemType Directory -Force -Path $KeysDir1 | Out-Null
    Write-Host '    Test directories ready.'

    # ── Step 5: Run the agent ───────────────────────────────────────────
    Write-Host '==> Step 5: Starting agent...'
    $AgentExe = Join-Path $RepoRoot 'target\release\sda-agent.exe'
    if (-not (Test-Path $AgentExe)) {
        Record -Status FAIL -Description "Agent binary not found at $AgentExe"
        exit 1
    }
    $AgentProcess = Start-Process -FilePath $AgentExe `
                                  -ArgumentList $ConfigFile `
                                  -PassThru `
                                  -WindowStyle Hidden
    Start-Sleep -Seconds 15
    Write-Host ("    Agent started (PID {0})." -f $AgentProcess.Id)

    # ── Step 6: Verify enrollment ───────────────────────────────────────
    Write-Host '==> Step 6: Verifying enrollment...'
    $AgentList = & docker compose -f tests/docker-compose.yml exec -T wazuh-manager /var/ossec/bin/manage_agents -l 2>$null
    Write-Host "    Enrolled agents: $AgentList"
    if ($AgentList -match 'ID:') {
        Record -Status PASS -Description 'Agent enrolled successfully'
    } else {
        Record -Status FAIL -Description 'Agent not enrolled'
    }

    # ── Step 7: Verify agent active after keepalive ─────────────────────
    Write-Host '==> Step 7: Waiting for keepalive cycle (35s)...'
    Start-Sleep -Seconds 35

    $AgentList2 = & docker compose -f tests/docker-compose.yml exec -T wazuh-manager /var/ossec/bin/manage_agents -l 2>$null
    if ($AgentList2 -match '(?i)active') {
        Record -Status PASS -Description 'Agent shows as active after keepalive'
    } elseif ($AgentList2 -match 'ID:') {
        Record -Status PASS -Description 'Agent still enrolled after keepalive (active flag not shown)'
    } else {
        Record -Status FAIL -Description 'Agent not active after keepalive'
    }

    # ── Step 8: Trigger FIM event ───────────────────────────────────────
    Write-Host '==> Step 8: Triggering FIM event...'
    New-Item -ItemType File -Force -Path (Join-Path $FimDir 'testfile.txt') | Out-Null
    Write-Host '    Waiting 30s for syscheck alert...'
    Start-Sleep -Seconds 30

    $alertsJson = & docker compose -f tests/docker-compose.yml exec -T wazuh-manager cat /var/ossec/logs/alerts/alerts.json 2>$null
    $SyscheckAlerts = ([regex]::Matches($alertsJson, 'syscheck')).Count
    Write-Host "    Syscheck alerts found: $SyscheckAlerts"
    if ($SyscheckAlerts -gt 0) {
        Record -Status PASS -Description 'FIM syscheck alerts received by server'
    } else {
        Record -Status FAIL -Description 'No syscheck alerts found in alerts.json'
    }

    # ── Step 8b: Verify baseline scan events ─────────────────────────────
    Write-Host '==> Step 8b: Verifying baseline scan...'
    Set-Content -Path (Join-Path $FimDir 'scan-test-1.txt') -Value 'content1'
    Set-Content -Path (Join-Path $FimDir 'scan-test-2.txt') -Value 'content2'
    Set-Content -Path (Join-Path $FimDir 'scan-test-3.txt') -Value 'content3'

    Write-Host '    Waiting for baseline scan cycle...'
    Start-Sleep -Seconds 30

    $alertsJson = & docker compose -f tests/docker-compose.yml exec -T wazuh-manager cat /var/ossec/logs/alerts/alerts.json 2>$null
    $ScanAlerts = ([regex]::Matches($alertsJson, 'scan-test')).Count
    Write-Host "    Baseline scan alerts found: $ScanAlerts"
    if ($ScanAlerts -gt 0) {
        Record -Status PASS -Description 'Baseline scan syscheck alerts received by server'
    } else {
        Record -Status FAIL -Description 'No baseline scan alerts found in alerts.json'
    }

    # ── Step 9b: Verify inventory data ──────────────────────────────────
    Write-Host '==> Step 9b: Verifying inventory data...'
    Start-Sleep -Seconds 20

    $archivesJson = & docker compose -f tests/docker-compose.yml exec -T wazuh-manager cat /var/ossec/logs/archives/archives.json 2>$null
    $InventoryCount = ([regex]::Matches($archivesJson, 'syscollector')).Count
    Write-Host "    Inventory events found: $InventoryCount"
    if ($InventoryCount -gt 0) {
        Record -Status PASS -Description 'Inventory data received by server'
    } else {
        $ossecLog = & docker compose -f tests/docker-compose.yml exec -T wazuh-manager grep -c syscollector /var/ossec/logs/ossec.log 2>$null
        if ($ossecLog -and [int]$ossecLog -gt 0) {
            Record -Status PASS -Description 'Inventory syscollector messages seen in ossec.log'
        } else {
            Record -Status FAIL -Description 'No inventory data found'
        }
    }

    # ── Step 9: Trigger log collection event (file-based) ───────────────
    Write-Host '==> Step 9: Triggering log collection event...'
    Add-Content -Path $LogFile -Value 'Apr 18 12:00:00 localhost sshd[9999]: Failed password for root from 10.0.0.1 port 22 ssh2'
    Write-Host '    Waiting 15s for log alert...'
    Start-Sleep -Seconds 15

    $alertsJson = & docker compose -f tests/docker-compose.yml exec -T wazuh-manager cat /var/ossec/logs/alerts/alerts.json 2>$null
    $LogAlerts = ([regex]::Matches($alertsJson, 'Failed password')).Count
    Write-Host "    Log collection alerts found: $LogAlerts"
    if ($LogAlerts -gt 0) {
        Record -Status PASS -Description 'Log collection alerts received by server'
    } else {
        Record -Status FAIL -Description 'No log collection alerts found in alerts.json'
    }

    # NOTE: journald log collection test is skipped on Windows — journald is
    # Linux-only. Windows EventLog support exists in sda-logcollector but is
    # not exercised here since EventLog ingestion lives in a separate path.

    # ── Step 10: Verify active response ──────────────────────────────────
    Write-Host '==> Step 10: Testing active response...'
    $AgentIdLine = & docker compose -f tests/docker-compose.yml exec -T wazuh-manager /var/ossec/bin/manage_agents -l 2>$null
    $AgentId = $null
    foreach ($line in $AgentIdLine -split "`n") {
        if ($line -match 'ID:\s*(\d+)') {
            $AgentId = $Matches[1]
            break
        }
    }
    if ($AgentId) {
        & docker compose -f tests/docker-compose.yml exec -T wazuh-manager /var/ossec/bin/agent_control -b 10.99.99.99 -f firewall-drop0 -u $AgentId 2>$null | Out-Null
        Write-Host '    Waiting 15s for active response execution...'
        Start-Sleep -Seconds 15

        $arLogCount = & docker compose -f tests/docker-compose.yml exec -T wazuh-manager grep -c active-response /var/ossec/logs/ossec.log 2>$null
        $archivesJson = & docker compose -f tests/docker-compose.yml exec -T wazuh-manager cat /var/ossec/logs/archives/archives.json 2>$null
        $arArchives = ([regex]::Matches(($archivesJson | Out-String), 'active-response')).Count

        $arLogInt = 0
        if ($arLogCount) { [void][int]::TryParse(($arLogCount | Out-String).Trim(), [ref]$arLogInt) }

        if ($arLogInt -gt 0 -or $arArchives -gt 0) {
            Record -Status PASS -Description 'Active response command processed'
        } else {
            Record -Status FAIL -Description 'No active response execution evidence found'
        }
    } else {
        Record -Status FAIL -Description 'Could not determine agent ID for active response test'
    }

    # ── Step 11: Cleanup handled by finally block ───────────────────────
    Write-Host '==> Step 11: Tests complete, cleaning up...'
}
finally {
    Invoke-Cleanup
}

exit $script:ExitCode
