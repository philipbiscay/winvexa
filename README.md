# Winvexa — Windows 11 Maintenance & Repair

Winvexa is a self-contained Windows desktop utility with a WPF graphical interface and an optional Command Prompt interface for advanced users. Double-clicking `Winvexa.exe`, or using the normal Start Menu/Desktop shortcut, opens a compact launcher with **Open Winvexa**, **Settings**, and **Exit** actions. Opening the dashboard closes the launcher; a second normal GUI launch activates the existing Winvexa window instead of opening a duplicate. The launcher and dashboard run as the `Winvexa.exe` Windows application without requiring administrator access. The installer also adds a separate advanced command-line repair shortcut, an optional desktop shortcut, and an uninstall entry in Windows Installed apps.

The dashboard provides Antivirus & Security, a diagnostic-only System Health Check, guided Windows repair, Fix My PC, maintenance tools, results, logs, Settings, and About. Winvexa is an independent Windows utility, not a replacement for Microsoft Defender. Defender remains responsible for system scans and its own remediation; Winvexa also provides a separate, limited local file analyzer and quarantine workflow without changing Defender protections.

Winvexa's reduced-motion behavior, safe visual transitions, and truthful security/watchlist state labels are specified in [SAFE-ANIMATION-AND-UI-STATE.md](./SAFE-ANIMATION-AND-UI-STATE.md).

## Prototype, migrated components, and production

- **Original Prototype:** the supplied 1.8.0 project is preserved at `..\Original Prototype\Winvexa`. This archived copy is not used by builds.
- **Rebuilt/Migrated Components:** `..\Rebuilt Components\README.md` records the compatibility review, component mapping, and replacements. The implementations run from the active production project; the archive is never compiled.
- **Current Production Winvexa:** this `Winvexa` project folder is the active .NET 8 WPF application and is the only source used by `build.ps1`.

The existing prototype already contains a modern WPF architecture and Microsoft Defender integration, so compatible maintenance, Liquid Glass, optimization, CLI, and cancellation workflows are retained rather than rewritten into an incompatible framework. The active production project includes its own on-demand local file analysis and quarantine workflow; it does not ship or run archived prototype antivirus code. Microsoft Defender remains the system scanner and owns remediation from Defender scans.

## Build and launch from the project

In VS Code, choose **Build & Launch Winvexa** from the Run button or the **Tasks: Run Task** command. The task publishes the existing project as a self-contained Windows x64 executable to the versioned `dist\Winvexa-Portable-<version>\Winvexa.exe` folder, then launches it. If that same executable is already open and responsive, the task reuses the running application instead of overwriting an in-use executable. An installed .NET 8 SDK is required to build from source; the launcher also checks standard SDK locations and the current user's Copilot SDK installation.

## Safety

- Direct file cleanup is limited to the current user's temporary and Internet cache folders. A file must have both last-access and last-write times at least 10 days old. Personal folders such as Documents, Desktop, Pictures, Videos, Music, and Downloads are never scanned.
- Cleanup lists the eligible categories and estimated size and requires an explicit `Y` confirmation. Read-only files and reparse points are skipped. The Recycle Bin requires a separate confirmation because emptying it cannot be undone.
- Windows cleanup is delegated to Microsoft's Disk Cleanup UI. Winvexa never deletes protected system files. Windows Update cache repair, when needed and explicitly approved, moves only `SoftwareDistribution\Download` to a timestamped backup and retains that backup; it does not remove update history.
- Drive checking uses `chkdsk <volume>` with no repair switches. Winvexa does not use `/scan`, which can perform online repairs, or queue offline repairs. The status-only check can be inconclusive or report spurious errors on a volume in use; access-denied checks are reported as incomplete rather than as confirmed file-system errors. A repair is never run automatically.
- Repair workflows use read-only `DISM /Online /Cleanup-Image /ScanHealth` and `sfc /verifyonly` checks before considering system repairs. These checks do not repair system files; deeper DISM RestoreHealth and SFC scannow operations are offered only when diagnostics indicate corruption and after user approval.
- Before a repair workflow can create a restore point, clean files, change Windows Update services/cache, or run DISM RestoreHealth/SFC, Winvexa identifies the installed Windows 11 edition, architecture, display version, build/revision, and servicing build; refuses an organization/local repair-source policy that would override Microsoft Windows Update; explicitly queries the Microsoft Windows Update service through the Windows Update Agent; verifies the Microsoft Authenticode signatures on Windows DISM and SFC; and runs read-only DISM CheckHealth. The Windows Update Agent checks applicable Microsoft software updates and Windows servicing supplies only payloads applicable to the running installation. No Windows ISO is cached or downloaded, no Windows feature upgrade is started, and DISM/SFC are blocked unless source preflight succeeds. The Stop button cancels the source query before repairs begin. Since Winvexa stores no verified offline image, an unavailable Microsoft source blocks repair and the log explains that Windows Update connectivity or administrator policy must be fixed before retrying.
- **Antivirus & Security** reads Microsoft Defender status using `Get-MpComputerStatus`, active detections and recent protection history using `Get-MpThreat`/`Get-MpThreatDetection`, and scan timestamps reported by Windows. If required data cannot be read, the page shows **Unable to verify** rather than assuming protection. Its overall state distinguishes Protected, Attention required, and Threat detected. Defender remediation is reviewed in Windows Security. Separately, Winvexa's selected-file analyzer checks a local SHA-256 knowledge base, Authenticode, supported startup/service/task references, and a point-in-time process/network snapshot. This limited analysis supplements but does not replace Defender and does not claim to continuously observe behaviors it cannot measure.
- **Unknown Threat Watchlist** enrolls files that remain unclassified after local analysis, lets them continue running, and stores a file-specific baseline. The installed setup registers a per-user background task that starts at sign-in; it polls active entries with a 30-second delay between completed observation cycles while that user session is running. Observation time accrues only across successful consecutive checks and pauses at sign-out, while Windows is off, or when checks fail. Thirty days of observation without a supported high-confidence finding is recorded as **Completed — No Malicious Behavior Observed**, not as a guarantee of safety. New observed capabilities or a changed file hash can trigger reassessment.
- The 30-day period never delays a confirmed sourced SHA-256 match or the validated high-confidence correlation of an unsigned user-writable executable, an exact persistence reference, and an established TCP connection. For those conditions, Winvexa attempts to stop processes only when their image path exactly matches the file, verifies quarantine by hash, records the outcome, and notifies the user. A high-confidence behavioral match remains classified as suspicious rather than confirmed malware. Less specific indicators are recorded for review and do not trigger automatic quarantine. Windows, installed-program, and Winvexa paths are protected.
- The local quarantine, detection records, watchlist, and security-event history are stored per Windows user under `%LOCALAPPDATA%\Winvexa`. Restore never executes a file. **Restore and Allow** applies only to the selected original path and exact SHA-256; a changed hash is assessed as a new file. Portable launches do not register the background task, so the watchlist is not continuously observed unless Winvexa is installed with `Winvexa-Setup.exe`.
- Quick, Full, and Custom system scans are performed by Microsoft Defender's `MpCmdRun.exe`; custom scans require a user-selected file or folder. The activity indicator and live log remain indeterminate because Windows does not expose a reliable scan percentage. Stop sends the documented `MpCmdRun.exe -Scan -Cancel` request and waits for the owned scan process to exit before reporting that it stopped. Defender's scan results and remediation remain separate from Winvexa's selected-file local analyzer and quarantine.
- Security-intelligence updates use `Update-MpSignature`, then read the reported Defender version and update time again. Winvexa reports success only when the update command succeeds and resulting status can be verified. It does not add exclusions, allow-lists, or change security settings.
- **Repair My PC** checks Defender health, intelligence age, and active detections. It explains protection issues and offers to open Windows Security. If definitions are more than seven days old, it asks before requesting an update and verifies the resulting status. It runs the existing Quick Scan only when protection is verified active; it does not run a Full Scan during routine repair.
- Defender is checked before updating signatures or scanning. Defender protections are not disabled or reconfigured.
- **Scan Windows** updates Defender security intelligence and runs a real Microsoft Defender Quick Scan. **System Health Check** performs available read-only DISM/SFC, drive, Windows Update, temporary-file, and Defender status checks without performing repairs or cleanup.
- Windows Update Scan & Repair checks the update services, WUA scan response, recent update history and operational error events, pending updates, and reboot state. Historical failures are reported separately from the current scan result.
- If Windows Update is not operational, Winvexa asks before starting eligible services, rebuilding the Download cache, or running DISM RestoreHealth followed by SFC. It does not alter service startup settings, and it verifies Windows Update again before reporting success.
- **Fix Windows Update Loop** additionally checks DISM component-store and SFC system-file health, identifies repeated failures for the same update from recent history, and can rebuild only the Windows Update Download cache or run DISM/SFC after separate confirmation. It rescans Windows Update and reports unresolved repeated updates or new failures without claiming success. If a restart is required, it offers Restart Now or Restart Later; it never restarts without confirmation.
- **Verify Windows Update** repeats the update scan, restart-state and system-health checks. A loop repair saves its pre-repair update titles and timestamp under `%LOCALAPPDATA%\Winvexa\WindowsUpdateLoopVerification.json` so verification after a restart can determine whether the previously affected update is still offered or failed again. Without that saved context, the action reports current health only and does not claim that an earlier loop was resolved.
- **Repair My PC** offers the dedicated loop repair when recent history contains at least two failed installations for the same update.
- **Fix My PC** runs a diagnosis-first on-demand repair: it checks whitelisted stale temporary files, read-only drive health, DISM/SFC health, Windows Update services/history/restart state, and Defender status/threat history. It offers only repairs relevant to findings, keeps cleanup and system/update changes behind explicit confirmations, and verifies system and Windows Update repairs before reporting success. Drive repair is never automatic; restart requirements and unresolved findings are listed for the user. Use **Save Report** on the Final report tab to export the repair results.
- The GUI uses stage-based indeterminate progress while work is active rather than presenting estimated percentages as measured completion. The About page shows Winvexa version/build details; Repair History lists dated session logs, and operation failures provide a clear summary with optional technical details while retaining full errors in the log.
- The 1.4.0 interface refresh applies one restrained 2029-era Windows visual system across the dashboard, optimization, Settings, About, repair history, status panels, and controls. Subtle window, hover, and press transitions provide feedback without slowing repair work or simulating scan progress.
- In 1.5.0, Settings adds an optional **Liquid Glass: ON / OFF** theme toggle. In 1.6.0, Liquid Glass is upgraded to request Windows Acrylic compositor blur behind each Winvexa window, with translucent layered surfaces and subtle animated highlights. The Windows compositor renders and updates the backdrop while Winvexa moves, rather than capturing or polling the desktop. If Acrylic is unavailable, Winvexa tries the Windows system backdrop and falls back to translucent surfaces; window text and controls remain opaque and readable. Theme colors transition smoothly between the standard opaque palette and glass surfaces. The selection is stored in `%LOCALAPPDATA%\Winvexa\settings.json` and restored on the next GUI launch. Older `LiquidGlassEnabled` preferences are also read when the current `LiquidGlass` field is absent or null.
- **Stop** immediately cancels cooperative work and terminates Winvexa-owned child processes that are safe to stop, including read-only diagnostics and the Winvexa-launched Windows Disk Cleanup process. Temporary-file scans and cleanup stop at directory/file boundaries, and no later workflow stage starts after cancellation. Windows operations without a safe cancellation API—such as DISM/SFC, Microsoft Defender scans, Windows Update Agent searches/installation, restore-point creation, Recycle Bin emptying, and drive optimization—finish their active operation. Winvexa remains visibly busy until the active operation ends rather than leaving it running invisibly. The UI then reports **Operation Stopped**, logs the cancellation, and does not report stopped work as successful. Optimization scan/apply/undo use the same cancellation behavior; already completed reversible changes remain available in the undo history.
- The main-window About entry opens **About This Program**, including the independent-project notice, current product/version/build, program description, latest feature highlights, recent fixes, and current release notes.
- Windows Update installation requires confirmation for each set of updates. The program checks again after installation, does not force a restart, and returns exit code `10` when a restart is needed.
- Windows 11 Optimization is scan-first and per-item: Winvexa never disables Windows services, applies a bulk debloat, uninstalls apps, changes power mode, disables accessibility effects, or automatically turns off gaming features.
- Privileged commands request elevation through the standard Windows UAC prompt. If UAC is declined, the command stops without running the elevated operation.

Windows may disable last-access timestamp updates; age is only a conservative extra filter, not proof that a file is disposable. Whitelisted folders, reparse-point checks, repeat validation before deletion, and user confirmation are the primary safeguards.

## Supported Windows 11 versions

The app's minimum OS build is Windows 11 build `22000` or later (x64). This includes Windows 11 21H2, 22H2, 23H2, 24H2, 25H2, and later builds when Windows still provides the documented tools/APIs. The installer and current published binary target x64 Windows 11. ARM64 source can be published separately; it is not included in the x64 installer.

Windows servicing support varies by edition and lifecycle. This build threshold describes the app's technical check, not Microsoft's servicing-support status for an individual Windows release.

## Install / uninstall

Run `Winvexa-Setup.exe` and follow the standard Windows installer. It installs under `{autopf}\Winvexa` by default and lets you change the destination in the wizard. The all-users install requests administrator approval through normal Windows UAC; the setup also offers a per-user installation option where supported. It creates a Start Menu link to the GUI and a second link for command-line repair, and creates an uninstall entry in **Settings → Apps → Installed apps**. The optional desktop shortcut opens the GUI (unchecked by default). The final page has a checked-by-default **Launch Winvexa** option; Finish launches the installed copy from the selected destination. The app opens without elevation and requests standard Windows UAC only when a selected operation needs administrator access. No repair starts as part of installation.

For automated deployment only, Inno Setup supports standard installer switches:

```text
Winvexa-Setup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-
Winvexa-Setup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP- /TASKS="desktopicon"
Winvexa-Setup.exe /SILENT
```

Silent installation still requires administrator approval for installing into Program Files (and may display UAC). The post-install GUI launch is intentionally skipped during silent installation. These switches install the program only; they do not run a repair. Uninstall from Installed apps or run the generated uninstaller in the installation directory. Uninstall removes only Winvexa's installed files and shortcuts; per-user repair logs and state under `%LOCALAPPDATA%\Winvexa` are retained.

The installer is a real Inno Setup package built from the published self-contained application, and the build verifies that the resulting `dist\Winvexa-Setup.exe` exists. For the installing Windows user, setup registers and starts the background watchlist task; uninstall removes that task but retains per-user security records and logs. Production distribution should use an Authenticode code-signing certificate; this project does not embed or assume a signing certificate, so the generated executable is unsigned and may receive a SmartScreen reputation warning.

## Command Prompt

Open Command Prompt and run the installed executable with a documented slash option. No arguments open the GUI; explicit command-line options select advanced CLI mode. The CLI displays timestamped progress and writes a detailed session log to `%LOCALAPPDATA%\Winvexa\Logs`.

```cmd
"%ProgramFiles%\Winvexa\Winvexa.exe" /scan
"%ProgramFiles%\Winvexa\Winvexa.exe" /repair
"%ProgramFiles%\Winvexa\Winvexa.exe" /cleanup
"%ProgramFiles%\Winvexa\Winvexa.exe" /drives
"%ProgramFiles%\Winvexa\Winvexa.exe" /defender
"%ProgramFiles%\Winvexa\Winvexa.exe" /defender --full
"%ProgramFiles%\Winvexa\Winvexa.exe" /update
"%ProgramFiles%\Winvexa\Winvexa.exe" /help
```

Commands:

| Command | Behavior |
|---|---|
| `/repair` | Full guided repair: restore point attempt, drive and cleanup scans, confirmed safe cleanup, optional read-only system/component checks, Defender Quick Scan, optional Windows Disk Cleanup, Windows Update check/install |
| `/scan` | Read-only drive and safe-temp diagnostics; never deletes files |
| `/cleanup` | Analyze stale whitelisted user temp/cache files; ask before deletion, Recycle Bin emptying, and Windows Disk Cleanup |
| `/drives` | Read-only NTFS drive health checks |
| `/defender` | Update signatures and run a Quick Scan |
| `/defender --full` | Update signatures and run a Full Scan |
| `/update` | Scan and diagnose Windows Update; offer confirmed repairs if needed, then ask before each applicable update set and report restart requirements |
| `/help` | Print commands and exit-code meanings |
| `/gui` | Open the graphical interface |

Normal GUI startup does not request elevation. When a selected operation needs administrator access, Winvexa explains why and requests approval through the standard Windows UAC prompt. Declining leaves the unelevated app available; the requested privileged operation does not run. Advanced CLI repair, drive, Defender, and Update commands use normal UAC elevation as needed. `/cleanup` runs without elevation and reports or skips locations that the current user cannot access. The parent Command Prompt waits while Windows runs an elevated command session. Approving UAC continues the requested command; declining returns exit code `2`.

### Exit codes

| Code | Meaning |
|---:|---|
| `0` | Successful |
| `1` | General error, unsupported OS, or invalid command |
| `2` | Administrator privileges required or UAC declined |
| `3` | Windows Update error |
| `4` | Defender error |
| `5` | Drive check error |
| `6` | Cleanup error |
| `10` | Restart required; no restart was forced |

Example for scripts:

```cmd
Winvexa.exe /scan
if errorlevel 1 echo Winvexa reported a diagnostic error: %ERRORLEVEL%
```

If multiple stages fail during `/repair`, the report still shows results for the other stages and the most significant non-zero exit status is returned (restart required has priority).

## Windows Update Scan & Repair

Use the **Windows Update Scan & Repair** button in the GUI, `/update` in Command Prompt, or run **Repair My PC** to include it near the end of the guided workflow. The diagnostics inspect `wuauserv`, BITS, Cryptographic Services, WUA scan success, reboot indicators, pending updates, the last 30 days of WUA installation history, and recent Windows Update operational error events. History/event entries are explicitly treated as historical when the current scan succeeds.

When a current scan or required service check fails, Winvexa may offer these actions one at a time:

1. Start eligible Windows Update services without changing their startup configuration.
2. Move only the Windows Update `SoftwareDistribution\Download` cache to a timestamped backup after stopping relevant services. Services that were running are restarted; the backup is retained for manual recovery and is never deleted by Winvexa.
3. Run Microsoft's `DISM /Online /Cleanup-Image /RestoreHealth`, followed by `sfc /scannow`, only after separate user approval. Output and exit codes are written to the report/log.

Disabled service configuration is not changed; it may be enforced by policy. A successful repair is reported only after a final WUA scan succeeds and the required service configuration is verified. If pending updates remain, each update set requires confirmation before download/installation. Winvexa never forces a reboot; it clearly reports when a restart prevents a final update check. Diagnostic warnings and Windows/HRESULT error codes are retained in the session log.

## Windows 11 Optimization

Open **Windows 11 Optimization** and use **Scan for Optimizations**. The scan is read-only and reports all ten requested areas: current-user and machine-wide startup entries, per-app background permissions exposed in the current-user Windows settings registry, enabled per-app notification settings exposed by Windows, transparency/taskbar effects, selected Windows suggestions and app-launch tracking settings, registered installed applications, the active power plan and laptop/desktop classification, fixed-drive media type, and Windows gaming/graphics settings pages. Only current-user startup items are directly changeable; machine-wide startup items are review-only.

No checkbox is selected automatically. Each proposed change shows its current and proposed state and explanation. **Review / Apply Selected Changes** asks for confirmation and attempts a restore point before reversible setting changes. If Windows cannot create a restore point, the user may cancel or continue with Winvexa's exact-value undo record. Supported reversible actions are restricted to current-user startup Run values/shortcuts and the specific per-user preference values shown in the report. Security-, driver-, and Windows-looking startup entries are protected from selection. Startup impact is shown as unavailable when Windows does not expose it through the inventory used by Winvexa.

For drive optimization, Winvexa offers an operation only when Windows reports an SSD or HDD type: SSDs use Windows `Optimize-Volume -ReTrim`, and HDDs use `Optimize-Volume -Defrag`. Unknown drive types are not optimized. The drive operation is individually confirmed and cannot be undone; Winvexa does not claim otherwise. It never runs a generic defragmentation command against an SSD.

Windows does not provide reliable last-use information for every desktop application. Winvexa inventories user-facing applications registered with Windows and shows any installer-provided size estimate, but it does not classify apps as unused from install dates or file timestamps. Selecting an app opens Installed apps in Windows Settings; the user must review and explicitly uninstall there. Power mode, gaming/graphics, and other review-only recommendations likewise open Windows Settings instead of being changed by Winvexa.

**Undo Previous Optimization** restores the exact reversible values and startup shortcuts saved by Winvexa. Drive optimization and changes made manually in Windows Settings are not reversible through this feature. The undo journal is stored under `%LOCALAPPDATA%\Winvexa\Optimizations\history.json`, separately from the per-session repair log. Each subsequent optimization is retained in history; Undo targets the most recent transaction that includes reversible Winvexa-managed settings.

**Repair My PC** can optionally open the optimization scanner near the end of its workflow. Scanning does not apply changes; every proposed action continues to require individual review and confirmation.

## Build source, installer, and portable package

See [DEVELOPING-FROM-USB.md](./DEVELOPING-FROM-USB.md) for requirements and the complete cross-computer transfer procedure. The project uses relative paths and has no third-party NuGet dependencies. The build computer needs Windows 11, .NET 8 SDK with WPF targeting support, PowerShell 5.1+, and Inno Setup 6 for the installer. These development tools are installed separately; no personal SDK, package cache, or computer-specific path is required.

Run this from PowerShell in the project folder:

```powershell
.\build.ps1
```

The script publishes a self-contained single-file `Winvexa.exe` to a versioned build directory, creates both the versioned portable package and the backwards-compatible portable folder, and compiles the x64 installer. Versioned build outputs avoid overwriting a shared publish executable while a prior application process still has it open. It resolves all project inputs relative to `build.ps1`, independent of the current directory or drive letter. Output files:

```text
bin\Release\net8.0-windows\win-x64\publish-1.9.0\Winvexa.exe
dist\Winvexa-Setup.exe
dist\Winvexa-Portable-1.9.0\Winvexa.exe
dist\Winvexa-Portable\Winvexa.exe
dist\Winvexa-Portable\README.txt
dist\Winvexa-Portable\winvexa.ico
```

To build the portable package without Inno Setup:

```powershell
.\build.ps1 -SkipInstaller
```

Validate the portable folder and launch its bundled executable with the CLI help smoke test:

```powershell
.\tests\Test-PortableBuild.ps1
```

Run the Windows process-runner cancellation regression tests:

```powershell
dotnet run --project .\tests\ProcessRunner.Tests\ProcessRunner.Tests.csproj -c Release
```

To publish a standalone ARM64 executable (without the x64 installer):

```powershell
.\build.ps1 -Runtime win-arm64 -SkipInstaller
```

The app itself is `asInvoker`; the GUI requests UAC through the standard Windows shell elevation action only for operations that require administrator access. The self-contained publish includes its .NET runtime, so end users do not need Visual Studio, the .NET SDK/runtime, Python, or other development tools.

## Troubleshooting

- **UAC was declined:** rerun the command and approve the standard Windows prompt; no elevated operation ran when it was declined.
- **Restore point unavailable:** System Protection may be disabled, a restore point may have been created recently, or policy may block it. The workflow records the error and continues with other stages.
- **Drive health unavailable:** CHKDSK requires an administrator token and the status-only check is limited to NTFS in Winvexa. Unsupported file systems are reported as skipped; access-denied checks are reported as incomplete, not as drive errors. No automatic repair command is run.
- **Defender unavailable/passive:** another antivirus or organizational policy may make Defender inactive. The utility reports the state and does not turn protections on or off.
- **Windows Update error:** review the service states, HRESULT, event/history warnings, and per-update results in the session log. A disabled service may be controlled by policy; Winvexa will not change its startup type. If cache recovery was approved, the timestamped Download backup is retained under `%WINDIR%\SoftwareDistribution`.
- **Disk Cleanup unavailable:** the app reports if `cleanmgr.exe` is absent. The utility never substitutes direct deletion of protected Windows files.
- **No temp files listed:** Windows may suppress last-access updates, or the files may be newer than 10 days. Only whitelisted locations are eligible.
- **Log file:** open the latest file under `%LOCALAPPDATA%\Winvexa\Logs`.

## Validation performed

For the 1.9.0 rebuild, validation includes the Windows Release build, portable self-contained publish, launcher-to-dashboard handoff, duplicate-GUI activation, Settings entry point, CLI help smoke test, installer-version/task configuration checks, process-runner cancellation regressions, Liquid Glass settings-schema compatibility, and synthetic watchlist/quarantine lifecycle tests. Watchlist tests cover the 30-day observation threshold, paused time across missed checks, behavior-based reassessment, immediate high-confidence containment, and persistence. Inno Setup is required to compile the installer and exercise installation/uninstallation; if it is not installed, those installer flows remain unvalidated. No real malware is used in testing.

Made by Philip Biscay
