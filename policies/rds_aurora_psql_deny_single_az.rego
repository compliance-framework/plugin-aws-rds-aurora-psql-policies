package compliance_framework.deny_single_az

violation[{}] if {
  not input.MultiAZ
}

title := "RDS Instance is deployed in multiple AZ"
