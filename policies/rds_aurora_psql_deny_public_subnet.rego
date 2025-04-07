package compliance_framework.deny_public_subnet

violation[{}] if {
  input.PubliclyAccessible
}

title := "RDS Instance is not publicly accessible"
