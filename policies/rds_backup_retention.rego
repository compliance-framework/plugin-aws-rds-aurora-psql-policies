package compliance_framework.rds_backup_retention

import future.keywords.in

# METADATA
# title: RDS backup retention meets policy
# description: Checks whether the current RDS or Aurora database backup retention period meets the configured minimum and does not exceed the maximum personal-information retention period.
# custom:
#   metric_ids:
#     - RDS_AVAILABILITY_BACKUP_RESTORE
#     - rds_backup_multiaz_pitr
#     - rds_confidential_data_controls
#     - RDS_PRIVACY_INFRASTRUCTURE_POSTURE
#   controls:
#     - ctrl-a1-2-008
#     - ctrl-a1-2-009
#     - ctrl-cc9-1-006
#     - ctrl-cc9-1-009
#     - ctrl-c1-1-004
#     - ctrl-c1-1-011
#     - ctrl-p4-2-002

config := object.get(input, "config", {})
policy_inputs := object.get(input, "policy_inputs", {})
resource := object.get(input, "resource", {})
resource_type := object.get(resource, "type", "")
resource_id := object.get(resource, "id", object.get(config, "db_instance_identifier", object.get(config, "db_cluster_identifier", "unknown")))
backup_retention_period := object.get(config, "backup_retention_period", 0)
minimum_days := object.get(policy_inputs, "minimum_backup_retention_days", 1)
maximum_pi_days := object.get(policy_inputs, "maximum_personal_information_retention_days", 365)

skip_reason := sprintf("Resource type %q is not an RDS database resource; this policy only applies to db-instance and db-cluster resources.", [resource_type]) if {
	not resource_type in {"db-instance", "db-cluster"}
}

title := sprintf("Validate RDS backup retention for %s", [resource_id])
description := sprintf("RDS resource %s reports backup_retention_period=%d days; required minimum is %d days and personal-information maximum is %d days.", [resource_id, backup_retention_period, minimum_days, maximum_pi_days])

violation[{"id": "backup_retention_too_short"}] if {
	resource_type in {"db-instance", "db-cluster"}
	backup_retention_period < minimum_days
}

violation[{"id": "backup_retention_exceeds_privacy_limit"}] if {
	resource_type in {"db-instance", "db-cluster"}
	backup_retention_period > maximum_pi_days
}
