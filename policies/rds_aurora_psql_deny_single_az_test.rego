package compliance_framework.deny_single_az

test_violation_single_az if {
  violation[_] with input as {
    "MultiAZ": false
  }
}