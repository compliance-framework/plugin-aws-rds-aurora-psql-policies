package compliance_framework.rds_network_boundary

import future.keywords.in

# METADATA
# title: RDS network boundary is private and scoped
# description: Checks whether the current RDS or Aurora database is private, attached to VPC security groups, and, for DB instances, associated with a DB subnet group.
# custom:
#   metric_ids:
#     - DATA_STORE_ENCRYPTION_ACCESS
#     - RDS_PRIVACY_INFRASTRUCTURE_POSTURE
#   controls:
#     - ctrl-cc6-7-001
#     - ctrl-cc6-7-002
#     - ctrl-cc6-7-004
#     - ctrl-cc6-7-005
#     - ctrl-p6-5-001
#     - ctrl-p6-5-003

config := object.get(input, "config", {})
resource := object.get(input, "resource", {})
resource_type := object.get(resource, "type", "")
resource_id := object.get(resource, "id", object.get(config, "db_instance_identifier", object.get(config, "db_cluster_identifier", "unknown")))
publicly_accessible := object.get(config, "publicly_accessible", false)
security_group_count := count(object.get(config, "vpc_security_groups", []))
subnet_group := object.get(config, "db_subnet_group", null)

skip_reason := sprintf("Resource type %q is not an RDS database resource; this policy only applies to db-instance and db-cluster resources.", [resource_type]) if {
	not resource_type in {"db-instance", "db-cluster"}
}

is_database_resource if {
	resource_type in {"db-instance", "db-cluster"}
}

default has_required_subnet_group := false

has_required_subnet_group if {
	resource_type != "db-instance"
}

has_required_subnet_group if {
	resource_type == "db-instance"
	subnet_group != null
	count(subnet_group) > 0
}

title := sprintf("Validate RDS network boundary for %s", [resource_id])
description := sprintf("RDS resource %s reports publicly_accessible=%v, %d VPC security groups, and subnet group evidence present=%v.", [resource_id, publicly_accessible, security_group_count, has_required_subnet_group])

violation[{"id": "database_publicly_accessible"}] if {
	is_database_resource
	publicly_accessible == true
}

violation[{"id": "vpc_security_groups_missing"}] if {
	is_database_resource
	security_group_count == 0
}

violation[{"id": "subnet_group_missing"}] if {
	is_database_resource
	not has_required_subnet_group
}
