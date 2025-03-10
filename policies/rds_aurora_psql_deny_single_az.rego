package compliance_framework.template.aws._deny_single_az

violation[{
  "title": "RDS instance is not Multi-AZ",
}] if {
  not input.MultiAZ
}