# Develop and build Winvexa from USB

The Winvexa source tree uses project-relative paths. Copy the entire `Winvexa`
folder to any writable local folder on the development computer (for example,
the root folder or a `Projects\Winvexa` subfolder) and run the build there.
The drive letter and folder name do not matter.

## Requirements on the development computer

- Windows 11 (x64 for the installer and default portable package).
- .NET 8 SDK with the Windows desktop/WPF targeting packs. The SDK installs
  those packs and supplies `dotnet`; the build may restore the framework
  reference packs from Microsoft's configured NuGet sources.
- Inno Setup 6 to build `Winvexa-Setup.exe`.
- PowerShell 5.1 or later.

Winvexa has no third-party NuGet package dependencies. The .NET SDK and Inno
Setup are separate tools and are not copied into the source tree: they have
their own installers, licensing terms, servicing, and machine-specific
configuration. Install them from their official distribution channels on each
development computer. Do not copy a developer's `bin`, `obj`, SDK, or package
cache directories as dependencies.

The end-user portable package is different: it contains a self-contained
single-file Winvexa executable with the .NET runtime bundled. A target Windows
11 PC does not need the SDK, Inno Setup, source code, or a separate .NET
runtime.

## Build from the copied folder

Open `Winvexa.sln` in Visual Studio to inspect and continue editing the WPF
project, or open PowerShell in the copied `Winvexa` directory to build. If script execution policy
prevents local scripts, run the build in a child PowerShell with a one-process
bypass rather than changing machine policy:

```powershell
.\Test-DevelopmentEnvironment.ps1
.\build.ps1
```

Each build checks a SHA-256 fingerprint of the source, tests, build scripts,
installer configuration, and release assets. Changed inputs automatically
increase the minor number by exactly one, update `Directory.Build.props`, and
add a `CHANGELOG.md` entry. For example, 1.9 becomes 1.10 and 2.3 becomes 2.4.
The major number is never automatically reset or changed; unchanged inputs do
not consume another version.

The preflight script reports missing development tools and does not download
or install software. Use `.\Test-DevelopmentEnvironment.ps1 -SkipInstaller`
when building only the portable package.

The script locates the project, icon, installer definition, publish output,
and portable instructions relative to its own directory. It does not depend
on the caller's current directory or a fixed USB drive letter.
Both build entry points automatically check project fingerprints and advance
the central Major.Minor version by exactly 0.1 when tracked inputs change.

The default x64 build produces:

```text
bin\Release\net8.0-windows\win-x64\publish-<version>\Winvexa.exe
dist\Winvexa-Setup.exe
dist\Winvexa-Portable-<version>\Winvexa.exe
dist\Winvexa-Portable\Winvexa.exe
dist\Winvexa-Portable\README.txt
dist\Winvexa-Portable\winvexa.ico
```

`Winvexa-Setup.exe` is the normal installer. Copy the complete
`dist\Winvexa-Portable` folder to the target PC for the portable version.
Build the portable package without the installer when Inno Setup is not
installed:

```powershell
.\build.ps1 -SkipInstaller
```

An ARM64 portable package can be published on an ARM64-capable development
computer with:

```powershell
.\build.ps1 -Runtime win-arm64 -SkipInstaller
```

That output is written to `dist\Winvexa-Portable-win-arm64`.

## Transfer and validate the project

Copy the whole source `Winvexa` folder to the USB drive, including
`Winvexa.sln`, `Winvexa.csproj`, `.xaml`/`.cs` source, `installer`, `portable`,
`tests`, `build.ps1`, icon, and documentation. Build caches under `bin` and
`obj` are generated and may be omitted when transferring; outputs under `dist`
may be copied if you also want to carry finished deliverables.

On the other PC, copy the project from USB to a writable local folder before
building, install the requirements above, open PowerShell in the copied
folder, and run `.\build.ps1`. To check the portable package, run:

```powershell
.\tests\Test-PortableBuild.ps1
```

The relocation test copies the source files (excluding generated `bin`, `obj`
and `dist` folders) to a new temporary location, builds from a different
working directory, validates the portable package, and checks the installer:

```powershell
.\tests\Test-RelocatedBuild.ps1
```

It requires both the .NET 8 SDK and Inno Setup 6. Use
`.\tests\Test-RelocatedBuild.ps1 -SkipInstaller` if Inno Setup is not installed.

Application logs and user settings intentionally live in the signed-in user's
`%LOCALAPPDATA%\Winvexa` directory, not beside the project or executable.
This is independent of the project/USB location and avoids writing repair
state to a removable drive.

Made by Philip Biscay
