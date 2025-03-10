package compliance_framework.template.aws._deny_no_iam_auth

violation[{
  "title": "IAM database authentication is not enabled",
}] if {
  not input.IamDatabaseAuthenticationEnabled
}
