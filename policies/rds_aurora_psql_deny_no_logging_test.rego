package compliance_framework.deny_no_logging

test_violation_no_logging if {
    count(violation) == 1 with input as {
        "EnabledCloudwatchLogsExports": ["postgresql"]
    }
}