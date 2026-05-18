package compliance_framework.rds_snapshot_encryption

import future.keywords.in

# METADATA
# title: RDS snapshot encryption is enabled
# description: Checks whether the current RDS or Aurora snapshot record is encrypted and has KMS key evidence. The collector emits standalone records for every manual snapshot and only the latest automated snapshot per database source.
# custom:
#   metric_ids:
#     - DATA_STORE_ENCRYPTION_ACCESS
#     - rds_backup_multiaz_pitr
#     - rds_confidential_data_controls
#     - RDS_PRIVACY_INFRASTRUCTURE_POSTURE
#   controls:
#     - ctrl-cc6-7-014
#     - ctrl-cc9-1-009
#     - ctrl-c1-1-011
#     - ctrl-c1-2-006
#     - ctrl-p4-3-003

config := object.get(input, "config", {})
resource := object.get(input, "resource", {})
resource_type := object.get(resource, "type", "")
resource_id := object.get(resource, "id", object.get(config, "snapshot_identifier", "unknown"))
snapshot_identifier := object.get(config, "snapshot_identifier", resource_id)
snapshot_type := object.get(config, "snapshot_type", "unknown")
snapshot_create_time := object.get(config, "snapshot_create_time", "")
encrypted := object.get(config, "encrypted", false)
kms_key_id := object.get(config, "kms_key_id", "")

skip_reason := sprintf("Resource type %q is not an RDS snapshot resource; this policy only applies to db-snapshot and db-cluster-snapshot resources.", [resource_type]) if {
	not resource_type in {"db-snapshot", "db-cluster-snapshot"}
}

is_snapshot_resource if {
	resource_type in {"db-snapshot", "db-cluster-snapshot"}
}

title := sprintf("Validate RDS snapshot encryption for %s", [resource_id])
description := sprintf("RDS snapshot %s (type=%s, created_at=%q) reports encrypted=%v and kms_key_id_present=%v.", [snapshot_identifier, snapshot_type, snapshot_create_time, encrypted, kms_key_id != ""])

violation[{"id": "snapshot_unencrypted"}] if {
	is_snapshot_resource
	encrypted != true
}

violation[{"id": "snapshot_kms_key_missing"}] if {
	is_snapshot_resource
	encrypted == true
	kms_key_id == ""
}
