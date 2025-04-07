package compliance_framework.deny_unencrypted_storage

violation[{}] if {
  not input.StorageEncrypted
}

title := "RDS Instance storage is encrypted"