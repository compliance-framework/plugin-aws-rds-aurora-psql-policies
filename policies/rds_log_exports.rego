package compliance_framework.rds_log_exports

import future.keywords.in

# METADATA
# title: RDS required log exports are enabled
# description: Checks whether the current RDS or Aurora database has all required CloudWatch log exports enabled for audit and processing records.
# custom:
#   metric_ids:
#     - DATA_STORE_ENCRYPTION_ACCESS
#     - RDS_PRIVACY_INFRASTRUCTURE_POSTURE
#   controls:
#     - ctrl-p4-2-004

config := object.get(input, "config", {})
policy_inputs := object.get(input, "policy_inputs", {})
resource := object.get(input, "resource", {})
resource_type := object.get(resource, "type", "")
resource_id := object.get(resource, "id", object.get(config, "db_instance_identifier", object.get(config, "db_cluster_identifier", "unknown")))
enabled_log_exports := object.get(config, "enabled_cloudwatch_logs_exports", [])
required_log_exports := object.get(policy_inputs, "required_log_exports", ["postgresql"])
missing_log_exports := {log | log := required_log_exports[_]; not log in enabled_log_exports}

skip_reason := sprintf("Resource type %q is not an RDS database resource; this policy only applies to db-instance and db-cluster resources.", [resource_type]) if {
	not resource_type in {"db-instance", "db-cluster"}
}

title := sprintf("Validate RDS log exports for %s", [resource_id])
description := sprintf("RDS resource %s has enabled log exports %v; required exports are %v; missing exports are %v.", [resource_id, enabled_log_exports, required_log_exports, missing_log_exports])

violation[{"id": "required_log_exports_missing"}] if {
	resource_type in {"db-instance", "db-cluster"}
	count(missing_log_exports) > 0
}
