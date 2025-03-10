package compliance_framework.template.aws._deny_no_automatic_backups

violation[{
  "title": "Automatic backups are not enabled",
}] if {
  input.BackupRetentionPeriod == 0
}