package compliance_framework.deny_no_automatic_backups

violation[{}] if {
  input.BackupRetentionPeriod == 0
}

title := "Automatic backups are enabled"
