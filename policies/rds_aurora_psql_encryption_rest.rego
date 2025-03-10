package compliance_framework.template.aws._deny_unencrypted_storage

violation[{
  "title": "RDS instance storage encryption is not enabled",
}] if {
  not input.StorageEncrypted
}