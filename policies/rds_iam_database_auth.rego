package compliance_framework.rds_iam_database_auth

import future.keywords.in

# METADATA
# title: RDS IAM database authentication is enabled
# description: Checks whether the current RDS or Aurora database supports IAM database authentication so access can be revoked through IAM identity and policy changes.
# custom:
#   metric_id: DATA_STORE_ENCRYPTION_ACCESS
#   controls:
#     - ctrl-cc6-2-014
#     - ctrl-cc6-2-018
#     - ctrl-cc6-7-003
#     - ctrl-cc6-7-004

config := object.get(input, "config", {})
resource := object.get(input, "resource", {})
resource_type := object.get(resource, "type", "")
resource_id := object.get(resource, "id", object.get(config, "db_instance_identifier", object.get(config, "db_cluster_identifier", "unknown")))
iam_auth_enabled := object.get(config, "iam_database_authentication_enabled", false)

skip_reason := sprintf("Resource type %q is not an RDS database resource; this policy only applies to db-instance and db-cluster resources.", [resource_type]) if {
	not resource_type in {"db-instance", "db-cluster"}
}

title := sprintf("Validate RDS IAM database authentication for %s", [resource_id])
description := sprintf("RDS resource %s reports iam_database_authentication_enabled=%v.", [resource_id, iam_auth_enabled])

violation[{"id": "iam_database_authentication_disabled"}] if {
	resource_type in {"db-instance", "db-cluster"}
	iam_auth_enabled != true
}
