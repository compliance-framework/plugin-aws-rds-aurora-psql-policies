package compliance_framework.rds_snapshot_status

import future.keywords.in

# METADATA
# title: RDS snapshot is available
# description: Checks whether the current RDS or Aurora snapshot record is in the available state. The collector emits standalone records for every manual snapshot and only the latest automated snapshot per database source.
# custom:
#   metric_ids:
#     - RDS_AVAILABILITY_BACKUP_RESTORE
#     - rds_backup_multiaz_pitr
#   controls:
#     - ctrl-a1-2-008
#     - ctrl-a1-2-010
#     - ctrl-cc9-1-009

config := object.get(input, "config", {})
resource := object.get(input, "resource", {})
resource_type := object.get(resource, "type", "")
resource_id := object.get(resource, "id", object.get(config, "snapshot_identifier", "unknown"))
snapshot_identifier := object.get(config, "snapshot_identifier", resource_id)
snapshot_type := object.get(config, "snapshot_type", "unknown")
snapshot_create_time := object.get(config, "snapshot_create_time", "")
status := object.get(config, "status", "")

skip_reason := sprintf("Resource type %q is not an RDS snapshot resource; this policy only applies to db-snapshot and db-cluster-snapshot resources.", [resource_type]) if {
	not resource_type in {"db-snapshot", "db-cluster-snapshot"}
}

is_snapshot_resource if {
	resource_type in {"db-snapshot", "db-cluster-snapshot"}
}

title := sprintf("Validate RDS snapshot availability for %s", [resource_id])
description := sprintf("RDS snapshot %s (type=%s, created_at=%q) reports status=%q; available snapshots are required for usable backup evidence.", [snapshot_identifier, snapshot_type, snapshot_create_time, status])

violation[{"id": "snapshot_not_available"}] if {
	is_snapshot_resource
	status != "available"
}
