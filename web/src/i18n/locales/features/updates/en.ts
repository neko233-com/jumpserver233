export default {
  updates: {
    checksum: "SHA-256",
    title: "Software updates",
    description: "Check published stable releases from the official JumpServer233 repository.",
    loading: "Loading update settings…",
    current: "Running version",
    lastAttempt: "Last attempt",
    lastSuccess: "Last successful check",
    nextCheck: "Next automatic check",
    never: "Not yet",
    soon: "Within one minute",
    unknownBuild:
      "This build has no stable release version. Version comparison is unavailable; use a versioned official package for release tracking.",
    check: "Check for updates",
    checking: "Checking…",
    releaseNotes: "Release notes",
    artifact: "Native package and checksum",
    artifactPending: "The native package for this system is not available yet.",
    automatic: "Automatically check for updates",
    interval: "Check interval (hours)",
    checkOnly:
      "Checks never install software or change business data. Stop the service and export a full backup before an upgrade.",
    save: "Save update settings",
    saved: "Update settings saved.",
    audit: "Recent update activity",
    states: {
      not_checked: "No release check yet.",
      no_release: "No published stable release is available.",
      current_unknown: "Latest stable release:",
      up_to_date: "No newer stable release. Latest:",
      update_available: "A newer stable release is available:",
    },
    errors: {
      conflict: "Settings changed. The current revision has been reloaded; review it and retry.",
      busy: "Another check is running. Try again shortly.",
      rate_limited: "Checks are rate limited. Wait at least one minute and try again.",
      invalid_release: "Release metadata could not be verified. No package was installed.",
      network:
        "The official release service is unavailable. The previous successful result is retained.",
      unavailable: "Could not load or save update information. Check permissions and retry.",
    },
    actions: {
      settings: "Settings changed",
      check: "Release check",
      maintenance: "Service drain changed",
    },
    automaticInstall: {
      title: "Automatic release preparation and installation",
      description:
        "Opt in to prepare official stable releases. Installation also requires the native supervisor and a maintenance window. Each policy revision and digest is attempted once.",
      disabled: "Automatic preparation and installation are off.",
      prepared: "Verified staged version: {{version}}",
      lastAttempt: "Last preparation attempt",
      nextAttempt: "Next preparation check",
      configure: "Configure automatic updates",
      mode: "Automatic update mode",
      modes: {
        off: "Off",
        prepare: "Prepare only",
        install: "Install within the maintenance window",
      },
      interval: "Preparation interval (hours)",
      window: "Daily window starts (UTC)",
      width: "Window length (minutes)",
      windowHelp:
        "UTC is fixed across timezone/daylight-saving changes. Work must drain before shutdown is committed within this window. A committed transaction continues to acceptance or recovery.",
      save: "Save automatic update policy",
      refresh: "Refresh preparation status",
      phases: {
        idle: "Waiting for preparation.",
        checking: "Checking the official stable release.",
        downloading: "Downloading the pinned archive.",
        staging: "Verifying and staging candidate files.",
        ready: "Candidate ready. Preparation alone does not install it.",
        failed: "Automatic preparation stopped with an error.",
        no_update: "No newer installable release was prepared.",
        attempted:
          "This policy/digest has already been attempted. Inspect installation results before authorizing another policy revision.",
      },
      failures: {
        attempt_limit: "The current policy reached its attempt limit. Inspect results and save an explicit new revision.",
        authorization:
          "The supervisor cannot authorize its own child. Check the persistent platform credential and loopback URL.",
        network: "The official release service was unavailable. The running service was retained.",
        invalid_release: "Official release metadata could not be verified.",
        integrity: "The archive or activation protocols did not match the pinned release.",
        rate_limited:
          "The official release service is rate limited. The next attempt remains scheduled.",
        interrupted:
          "Preparation was interrupted. Owned temporary downloads are recovered by the next supervisor.",
        canceled: "Preparation was cancelled.",
        unavailable:
          "Preparation or owned temporary cleanup could not complete. Inspect the native status before continuing.",
      },
      events: {
        policy: "Policy changed",
        check: "Release preparation started",
        ready: "Candidate verified",
        failed: "Preparation failed",
        no_update: "No candidate",
        attempted: "Candidate already attempted",
      },
    },
    maintenance: {
      stopping: "Shutdown committed. Waiting for the service to stop; cancellation is closed.",
      title: "Prepare for an upgrade",
      description:
        "Drain blocks new operations and pauses SSH monitoring and operation plans. Existing sessions and admitted work can finish. Counts represent active work, not unique connections. Stop the service before backup or installation. Draining resets on restart.",
      start: "Start draining",
      cancel: "Cancel draining",
      refresh: "Refresh drain status",
      open: "Accepting operations.",
      draining: "Draining. End remaining sessions or cancel running jobs to continue.",
      ready: "Tracked work has drained. Stop the service before backup or installation.",
      unsupported:
        "Drain control requires standalone mode. Coordinate cluster maintenance separately.",
      unavailable: "Could not read or change drain status. Check permissions and retry.",
      conflict:
        "The process or revision changed. Current status was reloaded; review it before retrying.",
      instance: "Process instance for CLI control",
      revision: "Revision {{revision}} · PID {{pid}}",
      activity: {
        ssh_routes: "SSH transports",
        http_requests: "Admitted requests and sockets",
        asset_cycles: "Inventory monitor cycles",
        credential_operations: "Credential operations",
        ssh_jobs: "Executing SSH jobs",
        probes: "Host probes",
        plan_dispatch: "Plan dispatch cycles",
        terminal_sessions: "Terminal sessions and tickets",
        desktop_sessions: "Desktop sessions",
        running_jobs: "Running jobs",
        database_queries: "Database queries",
        other: "Other active work",
      },
    },
    installation: {
      title: "Scheduled installation",
      description:
        "Install one verified staged version at a chosen time. The local supervisor drains sessions, stops this service, creates an encrypted checkpoint and validates startup. Existing sessions are never forcibly ended to meet a schedule.",
      unconfigured:
        "Managed native installation is not configured. Stage and install a baseline, then start jms update supervise with a protected checkpoint passphrase file.",
      supervisor:
        "Supervisor last reported: {{at}}. This timestamp does not prove it is still running.",
      prepare: "Schedule a staged version",
      staging:
        "Prepare the stable package with jms update download and stage. This action never chooses a different release automatically.",
      candidates: "Refresh verified candidates",
      target: "Target version and digest",
      choose: "Select a staged candidate",
      at: "Install after (local time)",
      timeout: "Maximum drain wait (seconds)",
      schedule: "Schedule installation",
      cancel: "Cancel installation",
      refresh: "Refresh installation status",
      history: "Recent installation activity",
      phases: {
        scheduled: "Scheduled",
        draining: "Waiting for sessions to drain",
        stopping: "Stopping service",
        installing: "Checkpoint and offline preflight",
        awaiting_start: "Validating candidate startup",
        succeeded: "Installation accepted",
        failed: "Installation stopped with an error",
        cancelled: "Installation cancelled",
      },
      failures: {
        activation_committed:
          "The new version failed after irreversible activation. New data was retained; use forward repair.",
        activation_failed:
          "Candidate startup could not complete. Inspect installation recovery state.",
        checkpoint_passphrase_unavailable:
          "The protected checkpoint passphrase could not be read. The service was retained.",
        installation_changed:
          "The managed installation revision changed. Review the current selection.",
        candidate_changed: "Candidate bytes could not be verified. The service was retained.",
        maintenance_unavailable:
          "The supervisor could not authorize maintenance on its own child. Check its platform identity and loopback URL.",
        drain_start_failed:
          "Drain start was not confirmed. Check the current drain state before retrying.",
        maintenance_changed:
          "Another operator changed maintenance. The supervisor did not override that decision.",
        drain_timeout:
          "Sessions did not finish within the wait period. Installation was cancelled and admission reopened.",
        reopen_failed:
          "Admission could not be reopened automatically. Inspect the current drain state.",
        service_exited:
          "The service exited before a confirmed stop. No scheduled installation was performed.",
        stop_unconfirmed: "Shutdown was not confirmed. Inspect the service before retrying.",
        service_stop_failed: "Service shutdown failed. Installation was not continued.",
        service_stop_timeout:
          "The service did not exit within the stop deadline. Installation was not continued.",
        installation_failed:
          "Installation failed. Inspect native installation status and recovery receipts.",
        supervisor_interrupted:
          "The supervisor was interrupted. This one-shot plan will not retry automatically.",
        activation_rolled_back:
          "Candidate startup failed before activation; the previous managed service was restored.",
        unknown: "Inspect the native installation and recovery status before continuing.",
      },
    },
  },
};
