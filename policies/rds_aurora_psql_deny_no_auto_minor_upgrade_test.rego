package compliance_framework.template.aws._deny_no_auto_minor_upgrade

test_violation_no_auto_minor_upgrade if {
  violation[_] with input as {
    "AutoMinorVersionUpgrade": false
  }
}

