package compliance_framework.template.aws._deny_no_logging

required_logs := ["postgresql", "audit"]

violation[{
  "title": "Database logs are not enabled",
}] if {
  missing_logs := {log | log := required_logs[_]; not log_enabled(input.EnabledCloudwatchLogsExports, log)}
  count(missing_logs) > 0
}

log_enabled(logs, log_name) if {
    some log in logs
    log == log_name
}
