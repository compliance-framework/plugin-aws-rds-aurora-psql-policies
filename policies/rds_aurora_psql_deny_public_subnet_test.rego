package compliance_framework.template.aws._deny_public_subnet

test_violation_public_subnet if {
  violation[_] with input as {
    "PubliclyAccessible": true
  }
}