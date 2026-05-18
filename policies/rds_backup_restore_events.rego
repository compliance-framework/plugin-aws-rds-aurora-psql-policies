package compliance_framework.rds_backup_restore_events

import future.keywords.in

# METADATA
# title: RDS backup and restore event evidence is present
# description: Checks whether the current RDS or Aurora database has RDS backup and restoration events in the collected dynamic evidence when those event requirements are enabled.
# custom:
#   metric_id: RDS_AVAILABILITY_BACKUP_RESTORE
#   controls:
#     - ctrl-a1-2-008
#     - ctrl-a1-2-010
#     - ctrl-a1-3-007

config := object.get(input, "config", {})
dynamic := object.get(input, "dynamic", {})
policy_inputs := object.get(input, "policy_inputs", {})
resource := object.get(input, "resource", {})
resource_type := object.get(resource, "type", "")
resource_id := object.get(resource, "id", object.get(config, "db_instance_identifier", object.get(config, "db_cluster_identifier", "unknown")))
require_backup_events := object.get(policy_inputs, "require_backup_events", false)
require_restore_events := object.get(policy_inputs, "require_restore_events", false)

skip_reason := sprintf("Resource type %q is not an RDS database resource; this policy only applies to db-instance and db-cluster resources.", [resource_type]) if {
	not resource_type in {"db-instance", "db-cluster"}
}

rds_event_has_category(event, category) if {
	some event_category in object.get(event, "event_categories", [])
	lower(event_category) == category
}

backup_event_count := count({event | event := object.get(dynamic, "rds_events", [])[_]; rds_event_has_category(event, "backup")})
restore_event_count := count({event | event := object.get(dynamic, "rds_events", [])[_]; rds_event_has_category(event, "restoration")})

title := sprintf("Validate RDS backup and restore events for %s", [resource_id])
description := sprintf("RDS resource %s has %d backup events and %d restoration events in the lookback window.", [resource_id, backup_event_count, restore_event_count])

violation[{"id": "backup_event_missing"}] if {
	resource_type in {"db-instance", "db-cluster"}
	require_backup_events == true
	backup_event_count == 0
}

violation[{"id": "restore_event_missing"}] if {
	resource_type in {"db-instance", "db-cluster"}
	require_restore_events == true
	restore_event_count == 0
}
