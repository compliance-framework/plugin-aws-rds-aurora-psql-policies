package compliance_framework.template.aws._deny_no_auto_minor_upgrade

violation[{
  "title": "Auto minor version upgrades are disabled",
}] if {
  not input.AutoMinorVersionUpgrade
}
