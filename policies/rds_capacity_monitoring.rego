package compliance_framework.rds_capacity_monitoring

import future.keywords.in

# METADATA
# title: RDS capacity monitoring evidence is present
# description: Checks whether the current RDS or Aurora database has enhanced monitoring enabled and CloudWatch capacity metrics when those evidence requirements are enabled by policy inputs.
# custom:
#   metric_ids:
#     - RDS_AVAILABILITY_BACKUP_RESTORE
#   controls:
#     - ctrl-a1-1-002

config := object.get(input, "config", {})
dynamic := object.get(input, "dynamic", {})
policy_inputs := object.get(input, "policy_inputs", {})
resource := object.get(input, "resource", {})
resource_type := object.get(resource, "type", "")
resource_id := object.get(resource, "id", object.get(config, "db_instance_identifier", object.get(config, "db_cluster_identifier", "unknown")))
monitoring_interval := object.get(config, "monitoring_interval", 0)
require_enhanced_monitoring := object.get(policy_inputs, "require_enhanced_monitoring", false)
require_capacity_metrics := object.get(policy_inputs, "require_capacity_metrics", false)
metrics := object.get(dynamic, "cloudwatch_metrics", {})

skip_reason := sprintf("Resource type %q is not an RDS database resource; this policy only applies to db-instance and db-cluster resources.", [resource_type]) if {
	not resource_type in {"db-instance", "db-cluster"}
}

default has_capacity_metric_data := false

metric_has_values(prefix) if {
	some key
	startswith(key, prefix)
	result := metrics[key]
	count(object.get(result, "values", [])) > 0
}

has_capacity_metric_data if {
	metric_has_values("cpuutil")
	metric_has_values("databaseconnections")
	metric_has_values("freestoragespace")
}

title := sprintf("Validate RDS capacity monitoring for %s", [resource_id])
description := sprintf("RDS resource %s reports monitoring_interval=%d, require_enhanced_monitoring=%v, require_capacity_metrics=%v, and capacity metric data present=%v.", [resource_id, monitoring_interval, require_enhanced_monitoring, require_capacity_metrics, has_capacity_metric_data])

violation[{"id": "enhanced_monitoring_missing"}] if {
	resource_type in {"db-instance", "db-cluster"}
	require_enhanced_monitoring == true
	monitoring_interval == 0
}

violation[{"id": "capacity_metric_data_missing"}] if {
	resource_type in {"db-instance", "db-cluster"}
	require_capacity_metrics == true
	not has_capacity_metric_data
}
