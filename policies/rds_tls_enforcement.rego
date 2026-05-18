package compliance_framework.rds_tls_enforcement

import future.keywords.in

# METADATA
# title: RDS TLS enforcement is configured
# description: Checks whether the current RDS or Aurora database parameter groups enforce SSL/TLS and whether DB instances report a CA certificate identifier.
# custom:
#   metric_ids:
#     - DATA_STORE_ENCRYPTION_ACCESS
#     - RDS_PRIVACY_INFRASTRUCTURE_POSTURE
#   controls:
#     - ctrl-cc6-7-001
#     - ctrl-cc6-7-007
#     - ctrl-cc6-7-008
#     - ctrl-cc6-7-010
#     - ctrl-cc6-7-011
#     - ctrl-p6-5-002

config := object.get(input, "config", {})
resource := object.get(input, "resource", {})
resource_type := object.get(resource, "type", "")
resource_id := object.get(resource, "id", object.get(config, "db_instance_identifier", object.get(config, "db_cluster_identifier", "unknown")))
ssl_enforcement := object.get(config, "ssl_enforcement", {})
ca_certificate_identifier := object.get(config, "ca_certificate_identifier", "")

skip_reason := sprintf("Resource type %q is not an RDS database resource; this policy only applies to db-instance and db-cluster resources.", [resource_type]) if {
	not resource_type in {"db-instance", "db-cluster"}
}

is_database_resource if {
	resource_type in {"db-instance", "db-cluster"}
}

ssl_enforced if {
	some group
	value := lower(sprintf("%v", [ssl_enforcement[group]]))
	value in {"1", "true", "on", "enabled", "required", "require"}
}

has_required_ca_certificate if {
	resource_type != "db-instance"
}

has_required_ca_certificate if {
	resource_type == "db-instance"
	ca_certificate_identifier != ""
}

title := sprintf("Validate RDS TLS enforcement for %s", [resource_id])
description := sprintf("RDS resource %s has SSL enforcement values %v and ca_certificate_identifier=%q.", [resource_id, ssl_enforcement, ca_certificate_identifier])

violation[{"id": "ssl_not_enforced"}] if {
	is_database_resource
	not ssl_enforced
}

violation[{"id": "ca_certificate_missing"}] if {
	is_database_resource
	not has_required_ca_certificate
}
