param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Install", "Uninstall")]
    [string]$Action
)

$ErrorActionPreference = "Stop"
$taskName = "Winvexa Unknown Threat Watchlist"
$logDirectory = Join-Path $env:LOCALAPPDATA "Winvexa\Logs"
$logPath = Join-Path $logDirectory "watchlist-worker.log"

function Write-TaskLog {
    param([string]$Message)
    New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
    Add-Content -LiteralPath $logPath -Value "[$([DateTimeOffset]::UtcNow.ToString('O'))] [Task setup] $Message"
}

try {
    if ($Action -eq "Uninstall") {
        $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($null -ne $existingTask) {
            Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        }
        Write-TaskLog "Removed the per-user background watchlist task."
        exit 0
    }

    $executablePath = Join-Path $PSScriptRoot "Winvexa.exe"
    if (-not (Test-Path -LiteralPath $executablePath -PathType Leaf)) {
        throw "Winvexa.exe was not found at '$executablePath'."
    }

    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    $actionDefinition = New-ScheduledTaskAction -Execute $executablePath -Argument "--watchlist-worker" -WorkingDirectory $PSScriptRoot
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
    $settings = New-ScheduledTaskSettingsSet `
        -MultipleInstances IgnoreNew `
        -ExecutionTimeLimit ([TimeSpan]::Zero) `
        -StartWhenAvailable `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries
    $principal = New-ScheduledTaskPrincipal `
        -UserId ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) `
        -LogonType Interactive `
        -RunLevel Limited

    Register-ScheduledTask `
        -TaskName $taskName `
        -Action $actionDefinition `
        -Trigger $trigger `
        -Settings $settings `
        -Principal $principal `
        -Description "Runs Winvexa's user-session-only unknown threat watchlist while this Windows user is signed in." `
        -Force | Out-Null
    Start-ScheduledTask -TaskName $taskName
    Write-TaskLog "Registered and started the per-user background watchlist task. Monitoring runs while this user is signed in."
}
catch {
    try {
        Write-TaskLog "Could not configure the background watchlist task: $($_.Exception.Message)"
    }
    catch {
        Write-Error "Could not configure or log the Winvexa watchlist task: $($_.Exception.Message)"
    }
    exit 1
}
