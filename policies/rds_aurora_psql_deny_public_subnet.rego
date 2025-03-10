package compliance_framework.template.aws._deny_public_subnet

violation[{
  "title": "RDS instance is deployed in a public subnet",
}] if {
  input.PubliclyAccessible
}