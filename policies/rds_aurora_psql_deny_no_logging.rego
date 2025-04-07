package compliance_framework.deny_no_logging

required_logs := ["postgresql", "audit"]

violation[{}] if {
  missing_logs := {log | log := required_logs[_]; not log_enabled(input.EnabledCloudwatchLogsExports, log)}
  count(missing_logs) > 0
}

log_enabled(logs, log_name) if {
    some log in logs
    log == log_name
}

title := "Database logs are enabled"