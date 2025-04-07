package compliance_framework.deny_no_auto_minor_upgrade

violation[{}] if {
  not input.AutoMinorVersionUpgrade
}

title := "Automatic minor version upgrades enabled"
