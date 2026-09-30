# Safe Animation and UI State Specification

Winvexa's interface reflects completed or currently executing application work. Visual effects are decorative only: they must not delay scans, containment, quarantine, notifications, cancellation, or user input, and must never imply progress the underlying operation did not report.

## Motion and performance

- Ordinary window appearance uses one interruptible 180 ms fade when Windows client-area animations are enabled. If Windows disables client-area animations, windows appear immediately. Threat dialogs bypass the fade so security information is shown immediately.
- Liquid Glass color and gradient transitions are limited to 220 ms and are applied only when Windows client-area animations are enabled. Changing reduced-motion preferences does not affect security-operation scheduling.
- Button hover and pressed states are immediate opacity changes. No continuous decorative animation, animated counters, or simulated progress is used.
- Progress controls may be indeterminate only while an actual asynchronous operation is running. They are not estimates of completed work.
- The watchlist UI refreshes at the worker's 30-second observation cadence. Observation duration advances only for successful supported checks; display formatting does not advance or accelerate its timer.

## Startup and failures

The launcher reports **Starting Winvexa...** until its window has loaded, then reports **Winvexa is ready**. The dashboard and its controls are available without waiting for an additional decorative startup sequence. A startup exception is shown with its actual message and a repair/reinstall recovery suggestion.

## Antivirus and quarantine states

| UI state | When it is displayed |
| --- | --- |
| Idle | No security operation is active. |
| Preparing | An operation has started; for Defender scans this includes updating security intelligence and preparing the scan. |
| Scanning | The Microsoft Defender scan process is running. Winvexa does not have exact live file counts or scan percentages, so it reports that limitation instead of inventing progress. |
| Threat Detected | A local analysis or supported watchlist check returned a confirmed/high-confidence result. Defender scan findings are presented only when Windows reports them. |
| Quarantining | Winvexa has entered its quarantine operation. |
| Quarantined | Winvexa verified the file in protected quarantine. |
| Containment Failed | A required containment or quarantine outcome was not verified; the failure details remain visible in status/log records. |
| Completed | The operation returned successfully. Defender's own findings and remediation status continue to be attributed to Windows. |
| Cancelled | Cancellation was requested and the operation returned or confirmed a stopped/incomplete result. |
| Error | The operation failed; the actual exception message is shown and technical details are written to the activity log. |

Winvexa uses Microsoft Defender for system scans. Its current integration does not provide Winvexa with a live stream of per-file scan counts or detections while that external scan is running. Therefore, Winvexa shows an active scan only while the scan process is active, never shows fabricated counters, and refreshes Defender's reported status after completion. Winvexa's local analyzer is an on-demand point-in-time check, not a real-time antivirus engine.

Threat notifications from the background watchlist remain visible until the user dismisses them. The on-demand threat dialog remains open until the user chooses **View Details** or **Close**. Notifications do not delay the containment operation that has already completed or failed.

## Unknown Threat Watchlist states

The watchlist presents a state derived from its persisted classification, confidence, outcome, and successfully accumulated observation duration:

- **Unknown · Under Observation · Day N / 30**: the latest assessment remains Unknown.
- **Suspicious · Day N / 30**: a supported suspicious classification remains below automatic containment threshold.
- **High Risk · Day N / 30**: a suspicious classification has high confidence but has not met the automatic-containment rule.
- **Potentially Unwanted · Day N / 30**: the latest assessment has a potentially unwanted classification; it is not relabeled as normal behavior or a confirmed threat.
- **Normal Behavior · Day N / 30**: the latest supported assessment is not suspicious. This is not a guarantee of safety.
- **Observation Complete · 30 / 30**: the existing completed status means 30 days of successful accumulated observation completed without a supported high-confidence detection. The record moves to history and enhanced monitoring stops.
- **Threat Detected**, **User Allowed**, **Containment Failed**, or **Quarantined**: the disposition persisted after a security detection. **Quarantined** is shown only when the quarantine record confirms that outcome.

The counter uses accumulated successful observation time, not wall-clock age or animation time. The worker performs supported point-in-time checks in polling cycles while the signed-in session is available; it is not continuous process telemetry. The baseline is a stored initial snapshot plus later observations, not machine-learning or a guarantee that future behavior is safe. A changed hash or later new evidence can be reassessed under the existing rules.

## State transitions and access

State text changes only when an operation or persisted record supplies new state. Scan buttons show **Scanning...** only while the selected Defender scan is active. Duplicate security operations remain disabled while a single operation is in progress. The UI remains responsive during asynchronous work, and stop/status controls remain available according to the existing operation's safe cancellation support.

Animations never gate security actions. Reduced-motion users retain every status, warning, control, and result; only decorative fades and Liquid Glass transitions are skipped. No page transition, loading skeleton, animated number, or notification timeout is allowed to conceal a failure or delay a security result.
