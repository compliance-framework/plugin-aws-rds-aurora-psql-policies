package compliance_framework.rds_snapshot_coverage

import future.keywords.in

# METADATA
# title: RDS database has snapshot coverage evidence
# description: Checks whether the current RDS database resource has selected snapshot evidence. The collector provides every manual snapshot and only the latest automated snapshot per database source, so this package validates snapshot coverage at the database level while per-snapshot packages validate individual snapshot records.
# custom:
#   metric_ids:
#     - RDS_AVAILABILITY_BACKUP_RESTORE
#     - rds_backup_multiaz_pitr
#   controls:
#     - ctrl-a1-2-008
#     - ctrl-a1-2-010
#     - ctrl-cc9-1-009

config := object.get(input, "config", {})
policy_inputs := object.get(input, "policy_inputs", {})
resource := object.get(input, "resource", {})
resource_type := object.get(resource, "type", "")
resource_id := object.get(resource, "id", object.get(config, "db_instance_identifier", object.get(config, "db_cluster_identifier", "unknown")))
snapshots := object.get(input, "snapshots", [])
require_snapshot_history := object.get(policy_inputs, "require_snapshot_history", true)
require_automated_snapshot := object.get(policy_inputs, "require_automated_snapshot", false)

skip_reason := sprintf("Resource type %q is not an RDS database resource; this policy only applies to db-instance and db-cluster resources.", [resource_type]) if {
	not resource_type in {"db-instance", "db-cluster"}
}

is_database_resource if {
	resource_type in {"db-instance", "db-cluster"}
}

available_snapshot_count := count({snapshot |
	snapshot := snapshots[_]
	object.get(snapshot, "status", "") == "available"
})

automated_available_snapshot_count := count({snapshot |
	snapshot := snapshots[_]
	object.get(snapshot, "status", "") == "available"
	lower(object.get(snapshot, "snapshot_type", "")) == "automated"
})

title := sprintf("Validate RDS snapshot coverage for %s", [resource_id])
description := sprintf("RDS resource %s has %d selected snapshots, %d available snapshots, and %d available automated snapshots; snapshot history required=%v and automated snapshot required=%v.", [resource_id, count(snapshots), available_snapshot_count, automated_available_snapshot_count, require_snapshot_history, require_automated_snapshot])

violation[{"id": "snapshot_history_missing"}] if {
	is_database_resource
	require_snapshot_history
	available_snapshot_count == 0
}

violation[{"id": "automated_snapshot_missing"}] if {
	is_database_resource
	require_automated_snapshot
	automated_available_snapshot_count == 0
}
