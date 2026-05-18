package compliance_framework.rds_multi_az_redundancy

import future.keywords.in

# METADATA
# title: RDS Multi-AZ redundancy is enabled
# description: Checks whether the current RDS or Aurora database reports Multi-AZ redundancy when the policy requires it.
# custom:
#   metric_ids:
#     - RDS_AVAILABILITY_BACKUP_RESTORE
#     - rds_backup_multiaz_pitr
#   controls:
#     - ctrl-a1-1-009
#     - ctrl-a1-2-006
#     - ctrl-a1-2-007
#     - ctrl-cc9-1-006

config := object.get(input, "config", {})
policy_inputs := object.get(input, "policy_inputs", {})
resource := object.get(input, "resource", {})
resource_type := object.get(resource, "type", "")
resource_id := object.get(resource, "id", object.get(config, "db_instance_identifier", object.get(config, "db_cluster_identifier", "unknown")))
multi_az := object.get(config, "multi_az", false)
require_multi_az := object.get(policy_inputs, "require_multi_az", true)

skip_reason := sprintf("Resource type %q is not an RDS database resource; this policy only applies to db-instance and db-cluster resources.", [resource_type]) if {
	not resource_type in {"db-instance", "db-cluster"}
}

title := sprintf("Validate RDS Multi-AZ redundancy for %s", [resource_id])
description := sprintf("RDS resource %s reports multi_az=%v while require_multi_az=%v.", [resource_id, multi_az, require_multi_az])

violation[{"id": "multi_az_missing"}] if {
	resource_type in {"db-instance", "db-cluster"}
	require_multi_az == true
	multi_az != true
}
