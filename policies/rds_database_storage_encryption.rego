package compliance_framework.rds_database_storage_encryption

import future.keywords.in

# METADATA
# title: RDS database storage encryption is enabled
# description: Checks whether the current RDS or Aurora database resource reports storage encryption and a KMS key for data at rest.
# custom:
#   metric_ids:
#     - DATA_STORE_ENCRYPTION_ACCESS
#     - rds_backup_multiaz_pitr
#     - rds_confidential_data_controls
#     - RDS_PRIVACY_INFRASTRUCTURE_POSTURE
#   controls:
#     - ctrl-cc6-5-004
#     - ctrl-cc6-7-008
#     - ctrl-cc6-7-009
#     - ctrl-cc9-1-006
#     - ctrl-c1-1-011
#     - ctrl-c1-2-006
#     - ctrl-p4-3-003

config := object.get(input, "config", {})
resource := object.get(input, "resource", {})
resource_type := object.get(resource, "type", "")
resource_id := object.get(resource, "id", object.get(config, "db_instance_identifier", object.get(config, "db_cluster_identifier", "unknown")))
storage_encrypted := object.get(config, "storage_encrypted", false)
kms_key_id := object.get(config, "kms_key_id", "")

skip_reason := sprintf("Resource type %q is not an RDS database resource; this policy only applies to db-instance and db-cluster resources.", [resource_type]) if {
	not resource_type in {"db-instance", "db-cluster"}
}

is_database_resource if {
	resource_type in {"db-instance", "db-cluster"}
}

title := sprintf("Validate RDS database storage encryption for %s", [resource_id])
description := sprintf("RDS database resource %s reports storage_encrypted=%v and kms_key_id_present=%v.", [resource_id, storage_encrypted, kms_key_id != ""])

violation[{"id": "storage_not_encrypted"}] if {
	is_database_resource
	storage_encrypted != true
}

violation[{"id": "kms_key_missing"}] if {
	is_database_resource
	storage_encrypted == true
	kms_key_id == ""
}
