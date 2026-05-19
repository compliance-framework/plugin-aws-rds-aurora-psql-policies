package compliance_framework.rds_pitr_freshness

import future.keywords.in

# METADATA
# title: RDS point-in-time recovery is current
# description: Checks whether the current RDS or Aurora database reports a latest restorable time and whether that timestamp is within the configured RPO lag threshold.
# custom:
#   metric_ids:
#     - RDS_AVAILABILITY_BACKUP_RESTORE
#     - rds_backup_multiaz_pitr
#     - rds_confidential_data_controls
#   controls:
#     - ctrl-a1-2-011
#     - ctrl-cc9-1-006
#     - ctrl-cc9-1-009
#     - ctrl-c1-1-011

config := object.get(input, "config", {})
collection := object.get(input, "collection", {})
policy_inputs := object.get(input, "policy_inputs", {})
resource := object.get(input, "resource", {})
resource_type := object.get(resource, "type", "")
resource_id := object.get(resource, "id", object.get(config, "db_instance_identifier", object.get(config, "db_cluster_identifier", "unknown")))
latest_restorable_time := object.get(config, "latest_restorable_time", "")
collected_at := object.get(collection, "collected_at", "")
maximum_pitr_lag_hours := object.get(policy_inputs, "maximum_pitr_lag_hours", 24)

skip_reason := sprintf("Resource type %q is not an RDS database resource; this policy only applies to db-instance and db-cluster resources.", [resource_type]) if {
	not resource_type in {"db-instance", "db-cluster"}
}

default pitr_lag_hours := -1

latest_restorable_time_present if {
	is_string(latest_restorable_time)
	latest_restorable_time != ""
}

pitr_lag_hours := hours if {
	latest_restorable_time_present
	collected_at != ""
	lag_ns := time.parse_rfc3339_ns(collected_at) - time.parse_rfc3339_ns(latest_restorable_time)
	hours := lag_ns / 3600000000000
}

pitr_current if {
	latest_restorable_time_present
	collected_at != ""
	pitr_lag_hours >= 0
	pitr_lag_hours <= maximum_pitr_lag_hours
}

title := sprintf("Validate RDS point-in-time recovery for %s", [resource_id])
description := sprintf("RDS resource %s reports latest_restorable_time=%q, collected_at=%q, PITR lag hours=%v, and allowed lag=%d hours.", [resource_id, latest_restorable_time, collected_at, pitr_lag_hours, maximum_pitr_lag_hours])

violation[{"id": "latest_restorable_time_missing"}] if {
	resource_type in {"db-instance", "db-cluster"}
	not latest_restorable_time_present
}

violation[{"id": "latest_restorable_time_stale"}] if {
	resource_type in {"db-instance", "db-cluster"}
	latest_restorable_time_present
	not pitr_current
}
