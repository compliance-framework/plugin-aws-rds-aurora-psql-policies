package compliance_framework.rds_snapshot_restore_access

import future.keywords.in

# METADATA
# title: RDS snapshot restore access is restricted
# description: Checks whether the current RDS or Aurora snapshot record is public, has unknown sharing posture, or is shared with AWS accounts outside the approved snapshot account list. The collector emits standalone records for every manual snapshot and only the latest automated snapshot per database source.
# custom:
#   metric_ids:
#     - DATA_STORE_ENCRYPTION_ACCESS
#     - rds_confidential_data_controls
#     - RDS_PRIVACY_INFRASTRUCTURE_POSTURE
#   controls:
#     - ctrl-cc6-7-005
#     - ctrl-cc6-7-006
#     - ctrl-c1-1-012
#     - ctrl-p6-5-003

policy_inputs := object.get(input, "policy_inputs", {})
resource := object.get(input, "resource", {})
config := object.get(input, "config", {})
resource_type := object.get(resource, "type", "")
resource_id := object.get(resource, "id", object.get(config, "snapshot_identifier", "unknown"))
snapshot_identifier := object.get(config, "snapshot_identifier", resource_id)
snapshot_type := object.get(config, "snapshot_type", "unknown")
snapshot_create_time := object.get(config, "snapshot_create_time", "")
approved_accounts := object.get(policy_inputs, "approved_snapshot_accounts", [])
fail_on_unknown_sharing := object.get(policy_inputs, "fail_on_unknown_snapshot_sharing", true)
public := object.get(config, "public", false)
shared_accounts := object.get(config, "shared_accounts", [])
unapproved_accounts := {account_id | account_id := shared_accounts[_]; not account_id in approved_accounts}

skip_reason := sprintf("Resource type %q is not an RDS snapshot resource; this policy only applies to db-snapshot and db-cluster-snapshot resources.", [resource_type]) if {
	not resource_type in {"db-snapshot", "db-cluster-snapshot"}
}

is_snapshot_resource if {
	resource_type in {"db-snapshot", "db-cluster-snapshot"}
}

title := sprintf("Validate RDS snapshot restore access for %s", [resource_id])
description := sprintf("RDS snapshot %s (type=%s, created_at=%q) reports public=%v and unapproved shared accounts=%v.", [snapshot_identifier, snapshot_type, snapshot_create_time, public, unapproved_accounts])

violation[{"id": "snapshot_public"}] if {
	is_snapshot_resource
	public == true
}

violation[{"id": "snapshot_sharing_unknown"}] if {
	is_snapshot_resource
	fail_on_unknown_sharing == true
	public == null
}

violation[{"id": "snapshot_shared_with_unapproved_account"}] if {
	is_snapshot_resource
	count(unapproved_accounts) > 0
}
