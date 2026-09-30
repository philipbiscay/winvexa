param(
    [string]$ProjectDirectory = $PSScriptRoot
)

$ErrorActionPreference = "Stop"
$projectDirectory = [System.IO.Path]::GetFullPath($ProjectDirectory)
$versionFile = Join-Path $projectDirectory "Directory.Build.props"
$stateFile = Join-Path $projectDirectory ".versioning-state.json"
$changelogFile = Join-Path $projectDirectory "CHANGELOG.md"
$lockFile = Join-Path $projectDirectory ".versioning-state.lock"
$projectRootPrefix = $projectDirectory.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar

function Get-ProjectRelativePath {
    param([string]$Path)

    if (-not $Path.StartsWith($projectRootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Versioned input '$Path' is not beneath the project directory."
    }
    return $Path.Substring($projectRootPrefix.Length)
}

if (-not (Test-Path -LiteralPath $versionFile -PathType Leaf)) {
    throw "Central version file not found: $versionFile."
}
if (-not (Test-Path -LiteralPath $changelogFile -PathType Leaf)) {
    throw "Release history not found: $changelogFile."
}

$lock = $null
for ($attempt = 0; $attempt -lt 50 -and $null -eq $lock; $attempt++) {
    try {
        $lock = [System.IO.File]::Open(
            $lockFile,
            [System.IO.FileMode]::OpenOrCreate,
            [System.IO.FileAccess]::ReadWrite,
            [System.IO.FileShare]::None)
    }
    catch [System.IO.IOException] {
        if ($attempt -eq 49) {
            throw "Could not acquire the versioning lock at '$lockFile'. Another Winvexa build may still be updating the version."
        }
        Start-Sleep -Milliseconds 200
    }
}

try {
    [xml]$versionMetadata = Get-Content -LiteralPath $versionFile -Raw
    $versionNode = $versionMetadata.Project.PropertyGroup.Version
    if ([string]$versionNode -notmatch '^(0|[1-9]\d*)\.(0|[1-9]\d*)$') {
        throw "The central Winvexa version must use Major.Minor format: '$versionNode'."
    }
    $currentMajor = [int]$Matches[1]
    $currentMinor = [int]$Matches[2]
    $currentVersion = "$currentMajor.$currentMinor"

    $ignoredDirectories = @("bin", "obj", "dist", ".git", ".vs")
    $excludedFiles = @(
        ".versioning-state.json",
        ".versioning-state.lock",
        "Directory.Build.props",
        "CHANGELOG.md"
    )
    $sourceFiles = Get-ChildItem -LiteralPath $projectDirectory -File -Recurse -Force |
        Where-Object {
            $relativePath = Get-ProjectRelativePath $_.FullName
            $segments = $relativePath -split '[\\/]'
            $_.Name -notin $excludedFiles -and
            $_.Name -notmatch '^\.versioning-state\.json\..*\.tmp$' -and
            -not ($segments | Where-Object { $_ -in $ignoredDirectories })
        } |
        Sort-Object { Get-ProjectRelativePath $_.FullName }

    $hashBuilder = [System.Text.StringBuilder]::new()
    $fileHashes = [ordered]@{}
    foreach ($file in $sourceFiles) {
        $relativePath = Get-ProjectRelativePath $file.FullName
        $fileHash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
        $fileHashes[$relativePath.Replace('\', '/')] = $fileHash
        [void]$hashBuilder.Append($relativePath.Replace('\', '/'))
        [void]$hashBuilder.Append("`0")
        [void]$hashBuilder.Append($fileHash)
        [void]$hashBuilder.Append("`n")
    }
    $fingerprintBytes = [System.Text.Encoding]::UTF8.GetBytes($hashBuilder.ToString())
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $fingerprint = [BitConverter]::ToString($sha256.ComputeHash($fingerprintBytes)).Replace("-", "")
    }
    finally {
        $sha256.Dispose()
    }

    $previousState = $null
    if (Test-Path -LiteralPath $stateFile -PathType Leaf) {
        try {
            $previousState = Get-Content -LiteralPath $stateFile -Raw | ConvertFrom-Json
        }
        catch {
            throw "The versioning state file is unreadable; refusing to risk reusing a version: $stateFile. $($_.Exception.Message)"
        }
    }
    if ($null -ne $previousState) {
        if ($previousState.Version -notmatch '^(0|[1-9]\d*)\.(0|[1-9]\d*)$') {
            throw "The versioning state is incomplete or invalid; refusing to risk reusing a version: $stateFile."
        }
        if ($previousState.Fingerprint -notmatch '^[A-Fa-f0-9]{64}$') {
            throw "The versioning fingerprint is incomplete or invalid; refusing to risk reusing a version: $stateFile."
        }
        $recordedMajor = [int]($previousState.Version -split '\.')[0]
        $recordedMinor = [int]($previousState.Version -split '\.')[1]
        if ($currentMajor -lt $recordedMajor -or
            ($currentMajor -eq $recordedMajor -and $currentMinor -lt $recordedMinor)) {
            throw "Central version $currentVersion is older than the last built version $($previousState.Version); refusing to reuse or roll back a release version."
        }
    }

    $changed = $null -eq $previousState -or
        $previousState.Fingerprint -ne $fingerprint -or
        $previousState.Version -ne $currentVersion
    if ($changed) {
        $nextVersion = "$currentMajor.$($currentMinor + 1)"

        $versionMetadata.Project.PropertyGroup.Version = $nextVersion
        $versionMetadata.Project.PropertyGroup.AssemblyVersion = "$nextVersion.0.0"
        $versionMetadata.Project.PropertyGroup.FileVersion = "$nextVersion.0.0"
        $versionMetadata.Project.PropertyGroup.InformationalVersion = $nextVersion
        $settings = [System.Xml.XmlWriterSettings]::new()
        $settings.Encoding = [System.Text.UTF8Encoding]::new($false)
        $settings.Indent = $true
        $settings.NewLineChars = "`r`n"
        $writer = [System.Xml.XmlWriter]::Create($versionFile, $settings)
        try {
            $versionMetadata.Save($writer)
        }
        finally {
            $writer.Dispose()
        }

        $changedFiles = @()
        if ($null -ne $previousState -and $null -ne $previousState.Files) {
            foreach ($path in $fileHashes.Keys) {
                $previousHash = $previousState.Files.PSObject.Properties[$path]
                if ($null -eq $previousHash -or $previousHash.Value -ne $fileHashes[$path]) {
                    $changedFiles += $path
                }
            }
            $changedFiles += @($previousState.Files.PSObject.Properties.Name |
                Where-Object { -not $fileHashes.Contains($_) })
        }
        elseif ($null -eq $previousState) {
            $changedFiles = @($fileHashes.Keys)
        }
        else {
            $changedFiles = @("Project inputs changed.")
        }
        $changeSummary = $changedFiles -join ", "
        $entry = "## $nextVersion`r`n`r`n- Automatically advanced one minor version for changed project inputs: $changeSummary.`r`n`r`n"
        $previousChangelog = Get-Content -LiteralPath $changelogFile -Raw
        $headingEnd = $previousChangelog.IndexOf("`n")
        if ($headingEnd -lt 0) {
            throw "Release history must begin with a Markdown title."
        }
        $updatedChangelog = $previousChangelog.Insert($headingEnd + 1, "`r`n$entry")
        [System.IO.File]::WriteAllText(
            $changelogFile,
            $updatedChangelog,
            [System.Text.UTF8Encoding]::new($false))

        Write-Host "Winvexa source changes detected; version increased from $currentVersion to $nextVersion."
        $currentVersion = $nextVersion
    }
    else {
        Write-Host "Winvexa source fingerprint is unchanged; retaining version $currentVersion."
    }

    $state = [ordered]@{
        Version = $currentVersion
        Fingerprint = $fingerprint
        Files = $fileHashes
    } | ConvertTo-Json
    $temporaryState = "$stateFile.$([Guid]::NewGuid().ToString('N')).tmp"
    [System.IO.File]::WriteAllText($temporaryState, $state, [System.Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temporaryState -Destination $stateFile -Force

    Write-Output $currentVersion
}
finally {
    if ($null -ne $lock) {
        $lock.Dispose()
    }
}
