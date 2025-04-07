package compliance_framework.deny_no_iam_auth

violation[{}] if {
  not input.IamDatabaseAuthenticationEnabled
}

title := "IAM database authentication enabled"
