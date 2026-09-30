param(
    [switch]$SkipInstaller
)

$ErrorActionPreference = "Stop"
$issues = [System.Collections.Generic.List[string]]::new()
$dotnet = Get-Command dotnet -ErrorAction SilentlyContinue

if (-not $dotnet) {
    $issues.Add(".NET 8 SDK is missing. Install the .NET 8 SDK with Windows desktop/WPF targeting support.")
}
else {
    $sdks = & $dotnet.Source --list-sdks
    if ($LASTEXITCODE -ne 0 -or -not ($sdks | Where-Object { $_ -match '^8\.0\.' })) {
        $issues.Add("No .NET 8 SDK was detected. Installed SDKs: $($sdks -join ', ').")
    }
    else {
        Write-Host ".NET 8 SDK: available ($($dotnet.Source))"
    }
}

if (-not $SkipInstaller) {
    $compiler = Get-Command ISCC.exe -ErrorAction SilentlyContinue
    if (-not $compiler) {
        $candidates = @()
        if (${env:ProgramFiles(x86)}) {
            $candidates += Join-Path ${env:ProgramFiles(x86)} "Inno Setup 6\ISCC.exe"
        }
        if ($env:ProgramFiles) {
            $candidates += Join-Path $env:ProgramFiles "Inno Setup 6\ISCC.exe"
        }
        $compilerPath = $candidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
    }
    else {
        $compilerPath = $compiler.Source
    }

    if ($compilerPath) {
        Write-Host "Inno Setup 6: available ($compilerPath)"
    }
    else {
        $issues.Add("Inno Setup 6 is missing. Install Inno Setup 6 to build Winvexa-Setup.exe, or run this check with -SkipInstaller for the portable build.")
    }
}
else {
    Write-Host "Inno Setup 6: not required for a portable-only build."
}

if ($issues.Count -gt 0) {
    foreach ($issue in $issues) {
        Write-Host "Missing requirement: $issue" -ForegroundColor Red
    }
    exit 1
}

Write-Host "Development environment is ready for the requested build."
