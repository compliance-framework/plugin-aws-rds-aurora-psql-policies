package compliance_framework.rds_deletion_protection

import future.keywords.in

# METADATA
# title: RDS deletion protection and final snapshot controls are configured
# description: Checks whether the current RDS or Aurora database has deletion protection enabled before destructive changes are allowed.
# custom:
#   metric_ids:
#     - DATA_STORE_ENCRYPTION_ACCESS
#     - rds_backup_multiaz_pitr
#     - rds_confidential_data_controls
#     - RDS_PRIVACY_INFRASTRUCTURE_POSTURE
#   controls:
#     - ctrl-cc6-5-001
#     - ctrl-cc6-7-003
#     - ctrl-cc6-7-006
#     - ctrl-cc9-1-006
#     - ctrl-c1-2-001
#     - ctrl-c1-2-006
#     - ctrl-p4-3-003

config := object.get(input, "config", {})
resource := object.get(input, "resource", {})
resource_type := object.get(resource, "type", "")
resource_id := object.get(resource, "id", object.get(config, "db_instance_identifier", object.get(config, "db_cluster_identifier", "unknown")))
deletion_protection := object.get(config, "deletion_protection", false)

skip_reason := sprintf("Resource type %q is not an RDS database resource; this policy only applies to db-instance and db-cluster resources.", [resource_type]) if {
	not resource_type in {"db-instance", "db-cluster"}
}

title := sprintf("Validate RDS deletion protection for %s", [resource_id])
description := sprintf("RDS resource %s reports deletion_protection=%v; false means the database can be deleted without first disabling a protective control.", [resource_id, deletion_protection])

violation[{"id": "deletion_protection_disabled"}] if {
	resource_type in {"db-instance", "db-cluster"}
	deletion_protection != true
}
