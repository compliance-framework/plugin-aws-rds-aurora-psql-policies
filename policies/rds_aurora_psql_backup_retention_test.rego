package compliance_framework.deny_no_automatic_backups

test_violation_no_automatic_backups if {
  violation[_] with input as {
    "BackupRetentionPeriod": 0
  }
}