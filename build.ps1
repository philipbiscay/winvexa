param(
    [ValidateSet("win-x64", "win-arm64")]
    [string]$Runtime = "win-x64",
    [switch]$SkipInstaller
)

$ErrorActionPreference = "Stop"
$projectDirectory = $PSScriptRoot
$project = Join-Path $projectDirectory "Winvexa.csproj"
$versioningScript = Join-Path $projectDirectory "Update-WinvexaVersion.ps1"
if (-not (Test-Path -LiteralPath $versioningScript -PathType Leaf)) {
    throw "Automatic versioning script is missing: $versioningScript."
}
$version = & $versioningScript -ProjectDirectory $projectDirectory
if ([string]::IsNullOrWhiteSpace($version)) {
    throw "Could not determine the Winvexa version from $versioningScript."
}
$publishDirectory = Join-Path $projectDirectory "bin\Release\net8.0-windows\$Runtime\publish-$version"
$installerScript = Join-Path $projectDirectory "installer\Winvexa.iss"
$portableDirectoryName = if ($Runtime -eq "win-x64") { "Winvexa-Portable" } else { "Winvexa-Portable-$Runtime" }
$portableDirectory = Join-Path $projectDirectory "dist\$portableDirectoryName"
$versionedPortableDirectoryName = if ($Runtime -eq "win-x64") {
    "Winvexa-Portable-$version"
} else {
    "Winvexa-Portable-$version-$Runtime"
}
$versionedPortableDirectory = Join-Path $projectDirectory "dist\$versionedPortableDirectoryName"
$portableReadme = Join-Path $projectDirectory "portable\README.txt"
$icon = Join-Path $projectDirectory "winvexa.ico"

$dotnetCommand = Get-Command dotnet -ErrorAction SilentlyContinue
if (-not $dotnetCommand) {
    throw "The .NET 8 SDK is required to build Winvexa. Install the .NET 8 SDK with Windows desktop/WPF targeting support, then reopen PowerShell."
}

$installedSdks = & $dotnetCommand.Source --list-sdks
if ($LASTEXITCODE -ne 0 -or -not ($installedSdks | Where-Object { $_ -match '^8\.0\.' })) {
    throw "A .NET 8 SDK was not found. Installed SDKs: $($installedSdks -join ', '). Install the .NET 8 SDK and its Windows desktop targeting pack."
}

& $dotnetCommand.Source publish $project -c Release -r $Runtime --self-contained true `
    /p:PublishSingleFile=true /p:IncludeNativeLibrariesForSelfExtract=true /p:IncludeAllContentForSelfExtract=true `
    --output $publishDirectory
if ($LASTEXITCODE -ne 0) {
    throw "dotnet publish failed with exit code $LASTEXITCODE."
}

if (-not (Test-Path -LiteralPath (Join-Path $publishDirectory "Winvexa.exe") -PathType Leaf)) {
    throw "The self-contained publish did not produce Winvexa.exe in $publishDirectory."
}
if (-not (Test-Path -LiteralPath $portableReadme -PathType Leaf)) {
    throw "The portable package instructions are missing: $portableReadme."
}

foreach ($directory in @($portableDirectory, $versionedPortableDirectory)) {
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $publishDirectory "Winvexa.exe") -Destination (Join-Path $directory "Winvexa.exe") -Force
    Copy-Item -LiteralPath $portableReadme -Destination (Join-Path $directory "README.txt") -Force
    Copy-Item -LiteralPath $icon -Destination (Join-Path $directory "winvexa.ico") -Force
}

if ($SkipInstaller) {
    Write-Host "Standalone executable: $publishDirectory\Winvexa.exe"
    Write-Host "Portable package: $versionedPortableDirectory"
    Write-Host "Portable compatibility folder: $portableDirectory"
    return
}
if ($Runtime -ne "win-x64") {
    throw "The current Inno Setup package is x64. Use -SkipInstaller when publishing the $Runtime executable."
}

$compiler = Get-Command ISCC.exe -ErrorAction SilentlyContinue
if (-not $compiler) {
    $candidates = @(
        (Join-Path ${env:ProgramFiles(x86)} "Inno Setup 6\ISCC.exe"),
        (Join-Path $env:ProgramFiles "Inno Setup 6\ISCC.exe"),
        (Join-Path $env:LOCALAPPDATA "Programs\Inno Setup 6\ISCC.exe")
    )
    $compilerPath = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
}
else {
    $compilerPath = $compiler.Source
}

if (-not $compilerPath) {
    throw "Inno Setup 6 was not found. Install it, or pass -SkipInstaller to build only Winvexa.exe."
}

Push-Location (Split-Path -Parent $installerScript)
try {
    & $compilerPath "/DAppVersion=$version" (Split-Path -Leaf $installerScript)
}
finally {
    Pop-Location
}
if ($LASTEXITCODE -ne 0) {
    throw "Inno Setup compilation failed with exit code $LASTEXITCODE."
}

$installerOutput = Join-Path $projectDirectory "dist\Winvexa-Setup.exe"
if (-not (Test-Path -LiteralPath $installerOutput -PathType Leaf)) {
    throw "Inno Setup reported success but did not produce the expected installer: $installerOutput."
}
if ((Get-Item -LiteralPath $installerOutput).Length -lt 1MB) {
    throw "The generated installer is unexpectedly small and may be incomplete: $installerOutput."
}

Write-Host "Standalone executable: $publishDirectory\Winvexa.exe"
Write-Host "Portable package: $versionedPortableDirectory"
Write-Host "Portable compatibility folder: $portableDirectory"
Write-Host "Installer: $installerOutput"
