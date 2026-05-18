package compliance_framework.rds_management_audit_events

import future.keywords.in
import future.keywords.contains

# METADATA
# title: RDS management audit events are present
# description: Checks whether CloudTrail evidence contains RDS management and access-removal events for the current RDS or Aurora resource when those dynamic checks are enabled.
# custom:
#   metric_ids:
#     - DATA_STORE_ENCRYPTION_ACCESS
#     - rds_confidential_data_controls
#     - RDS_PRIVACY_INFRASTRUCTURE_POSTURE
#   controls:
#     - ctrl-cc6-2-015
#     - ctrl-cc6-2-019
#     - ctrl-cc6-3-004
#     - ctrl-cc6-3-013
#     - ctrl-cc6-7-016
#     - ctrl-cc6-7-018

config := object.get(input, "config", {})
dynamic := object.get(input, "dynamic", {})
policy_inputs := object.get(input, "policy_inputs", {})
resource := object.get(input, "resource", {})
resource_type := object.get(resource, "type", "")
resource_id := object.get(resource, "id", object.get(config, "db_instance_identifier", object.get(config, "db_cluster_identifier", "unknown")))

skip_reason := sprintf("Resource type %q is not an RDS database resource; this policy only applies to db-instance and db-cluster resources.", [resource_type]) if {
	not resource_type in {"db-instance", "db-cluster"}
}

cloudtrail_events contains event if {
	event := object.get(dynamic, "cloudtrail_events", [])[_]
}

cloudtrail_events contains event if {
	event := object.get(dynamic, "account_cloudtrail_events", [])[_]
	raw := object.get(event, "cloudtrail_event", "")
	raw != ""
	payload := json.unmarshal(raw)
	params := object.get(payload, "requestParameters", {})
	db_instance_id := object.get(params, "dBInstanceIdentifier", object.get(params, "DBInstanceIdentifier", ""))
	db_instance_id == resource_id
}

cloudtrail_events contains event if {
	event := object.get(dynamic, "account_cloudtrail_events", [])[_]
	raw := object.get(event, "cloudtrail_event", "")
	raw != ""
	payload := json.unmarshal(raw)
	params := object.get(payload, "requestParameters", {})
	db_cluster_id := object.get(params, "dBClusterIdentifier", object.get(params, "DBClusterIdentifier", ""))
	db_cluster_id == resource_id
}

event_count_for(name) := count({event | event := cloudtrail_events[_]; object.get(event, "event_name", "") == name})

has_event_name(name) if {
	event_count_for(name) > 0
}

default has_rds_management_event := false

has_rds_management_event if {
	some name in {
		"CreateDBInstance",
		"CreateDBCluster",
		"ModifyDBInstance",
		"ModifyDBCluster",
		"ModifyDBParameterGroup",
		"ModifyDBClusterParameterGroup",
		"DeleteDBInstance",
		"DeleteDBCluster",
		"DeleteDBSnapshot",
		"DeleteDBClusterSnapshot",
		"ModifyDBSnapshotAttribute",
		"ModifyDBClusterSnapshotAttribute",
		"RevokeDBSecurityGroupIngress",
	}
	has_event_name(name)
}

default has_access_removal_event := false

has_access_removal_event if {
	has_event_name("DeleteUser")
}

has_access_removal_event if {
	has_event_name("DetachRolePolicy")
}

has_access_removal_event if {
	has_event_name("RevokeDBSecurityGroupIngress")
}

require_access_removal_events := object.get(policy_inputs, "require_access_removal_events", false)
require_rds_management_audit_events := object.get(policy_inputs, "require_rds_management_audit_events", false)

title := sprintf("Validate RDS management audit events for %s", [resource_id])
description := sprintf("RDS resource %s has access-removal events present=%v and RDS management events present=%v.", [resource_id, has_access_removal_event, has_rds_management_event])

violation[{"id": "access_removal_event_missing"}] if {
	resource_type in {"db-instance", "db-cluster"}
	require_access_removal_events == true
	not has_access_removal_event
}

violation[{"id": "rds_management_audit_event_missing"}] if {
	resource_type in {"db-instance", "db-cluster"}
	require_rds_management_audit_events == true
	not has_rds_management_event
}
