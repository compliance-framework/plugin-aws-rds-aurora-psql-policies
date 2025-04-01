package compliance_framework.template.aws._deny_no_logging

# METADATA
# title: Ensure required database logs are enabled
# description: Verifies that the necessary database logs are enabled and exported to CloudWatch to ensure auditability and security monitoring.
# custom:
#   controls:
#     - SAMA_CSF_1.0
#     - SAMA_ITGF_1.0
#     - SAMA_RMG_1.0
#     - SAMA_CCF_1.0
#   schedule: "* * * * * *"


controls := [
    # SAMA Cyber Security Framework v1.0
    {
        "class": "SAMA_CSF_1.0",
        "control-id": "3.3.6", # Data Protection
        "statement-ids": [
            "3", # Ensure proper logging and monitoring of sensitive data access.
        ],
    },
    # SAMA IT Governance Framework v1.0
    {
        "class": "SAMA_ITGF_1.0",
        "control-id": "3.3.2", # Logging and Monitoring
        "statement-ids": [
            "1", # Ensure systems log sensitive access events for audit and security purposes.
        ],
    },
    # SAMA Risk Management Guidelines v1.0
    {
        "class": "SAMA_RMG_1.0",
        "control-id": "3.4.1", # Audit and Monitoring
        "statement-ids": [
            "2", # Implement audit trails and monitoring for sensitive activities.
        ],
    },
    # SAMA Cloud Computing Framework v1.0
    {
        "class": "SAMA_CCF_1.0",
        "control-id": "3.1.4", # Cloud Data Protection
        "statement-ids": [
            "3", # Ensure logging and monitoring are implemented for cloud-based databases.
        ],
    },
]

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
