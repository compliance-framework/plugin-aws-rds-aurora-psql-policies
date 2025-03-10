package compliance_framework.template.aws._deny_unencrypted_storage

test_violation_unencrypted_storage if {
  violation[_] with input as {
    "StorageEncrypted": false
  }
}