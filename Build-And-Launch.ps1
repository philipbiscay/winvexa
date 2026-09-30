param()

$ErrorActionPreference = 'Stop'

$projectDirectory = $PSScriptRoot
$projectFile = Join-Path $projectDirectory 'Winvexa.csproj'
$versioningScript = Join-Path $projectDirectory 'Update-WinvexaVersion.ps1'
if (-not (Test-Path -LiteralPath $versioningScript -PathType Leaf)) {
    throw "Automatic versioning script is missing: '$versioningScript'."
}
$version = & $versioningScript -ProjectDirectory $projectDirectory
if ([string]::IsNullOrWhiteSpace($version)) {
    throw "Could not determine the application version from '$versioningScript'."
}

$dotnetCandidates = @()
$dotnet = Get-Command dotnet -ErrorAction SilentlyContinue
if ($dotnet) {
    $dotnetCandidates += $dotnet.Source
}

$dotnetCandidates += @(
    (Join-Path $env:ProgramFiles 'dotnet\dotnet.exe'),
    (Join-Path ${env:ProgramFiles(x86)} 'dotnet\dotnet.exe')
)

$sessionSdkDirectory = Join-Path $env:USERPROFILE '.copilot\session-state'
if (Test-Path -LiteralPath $sessionSdkDirectory -PathType Container) {
    $sdkHosts = Get-ChildItem -Path (Join-Path $sessionSdkDirectory '*\files\dotnet-sdk\dotnet.exe') `
        -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending
    if ($sdkHosts) {
        $dotnetCandidates += $sdkHosts.FullName
    }
}

$dotnetPath = $null
foreach ($candidate in ($dotnetCandidates | Where-Object { $_ } | Select-Object -Unique)) {
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        continue
    }

    $installedSdks = & $candidate --list-sdks 2>$null
    if ($LASTEXITCODE -eq 0 -and ($installedSdks | Where-Object { $_ -match '^\s*8\.0\.\d+' })) {
        $dotnetPath = $candidate
        break
    }
}

if (-not $dotnetPath) {
    throw 'The .NET SDK was not found. Install the .NET 8 SDK, then run this task again.'
}

$publishDirectory = Join-Path $projectDirectory "dist\Winvexa-Portable-$version"
$executable = Join-Path $publishDirectory 'Winvexa.exe'
$portableReadme = Join-Path $projectDirectory 'portable\README.txt'
$applicationIcon = Join-Path $projectDirectory 'winvexa.ico'

$alreadyRunning = Get-Process -Name 'Winvexa' -ErrorAction SilentlyContinue |
    Where-Object {
        $_.MainWindowHandle -ne [IntPtr]::Zero -and
        $_.Path -and
        [StringComparer]::OrdinalIgnoreCase.Equals($_.Path, $executable)
    } |
    Select-Object -First 1
if ($alreadyRunning) {
    if (-not $alreadyRunning.Responding) {
        throw 'Winvexa is already open but is not responding. Close it before rebuilding.'
    }
    Write-Host "Winvexa is already open and responsive (PID $($alreadyRunning.Id)); requesting activation of the existing window."
    Start-Process -FilePath $executable -ArgumentList '--gui' -WorkingDirectory $publishDirectory
    return
}

$publishArguments = @(
    'publish'
    $projectFile
    '-c', 'Release'
    '-r', 'win-x64'
    '--self-contained', 'true'
    '-p:PublishSingleFile=true'
    '-p:IncludeNativeLibrariesForSelfExtract=true'
    '-p:IncludeAllContentForSelfExtract=true'
    '-p:DebugType=None'
    '-p:DebugSymbols=false'
    '--output', $publishDirectory
)

Write-Host "Building Winvexa $version as a self-contained Windows x64 application..."
Push-Location $projectDirectory
try {
    & $dotnetPath @publishArguments
    if ($LASTEXITCODE -ne 0) {
        throw "Winvexa publish failed with exit code $LASTEXITCODE."
    }
}
finally {
    Pop-Location
}

if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
    throw "The build completed without producing the expected application: '$executable'."
}

foreach ($resource in @($portableReadme, $applicationIcon)) {
    if (-not (Test-Path -LiteralPath $resource -PathType Leaf)) {
        throw "A required portable release resource is missing: '$resource'."
    }
}
Copy-Item -LiteralPath $portableReadme -Destination (Join-Path $publishDirectory 'README.txt') -Force
Copy-Item -LiteralPath $applicationIcon -Destination (Join-Path $publishDirectory 'winvexa.ico') -Force

Write-Host "Launching $executable"
$application = Start-Process -FilePath $executable -WorkingDirectory $publishDirectory -PassThru
if (-not $application.WaitForInputIdle(15000)) {
    $application.Refresh()
    if ($application.HasExited) {
        throw "Winvexa closed during startup (exit code $($application.ExitCode))."
    }
}

$application.Refresh()
if ($application.HasExited) {
    throw "Winvexa closed during startup (exit code $($application.ExitCode))."
}

Write-Host "Winvexa is running (PID $($application.Id))."
