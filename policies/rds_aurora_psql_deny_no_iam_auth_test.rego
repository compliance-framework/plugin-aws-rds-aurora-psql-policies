package compliance_framework.template.aws._deny_no_iam_auth

test_violation_no_iam_auth if {
  violation[_] with input as {
    "IamDatabaseAuthenticationEnabled": false
  }
}

