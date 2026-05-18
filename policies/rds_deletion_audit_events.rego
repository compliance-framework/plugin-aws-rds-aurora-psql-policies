package compliance_framework.rds_deletion_audit_events

import future.keywords.in
import future.keywords.contains

# METADATA
# title: RDS deletion audit events are controlled
# description: Checks whether CloudTrail deletion evidence exists when required and whether observed RDS deletion events preserve a final snapshot.
# custom:
#   metric_ids:
#     - DATA_STORE_ENCRYPTION_ACCESS
#     - rds_confidential_data_controls
#     - RDS_PRIVACY_INFRASTRUCTURE_POSTURE
#   controls:
#     - ctrl-cc6-5-001
#     - ctrl-cc6-7-006
#     - ctrl-cc6-7-009
#     - ctrl-c1-2-001
#     - ctrl-c1-2-006
#     - ctrl-p4-3-003

config := object.get(input, "config", {})
dynamic := object.get(input, "dynamic", {})
policy_inputs := object.get(input, "policy_inputs", {})
resource := object.get(input, "resource", {})
resource_type := object.get(resource, "type", "")
resource_id := object.get(resource, "id", object.get(config, "db_instance_identifier", object.get(config, "db_cluster_identifier", "unknown")))
require_deletion_audit_events := object.get(policy_inputs, "require_deletion_audit_events", false)
require_disposal_audit_events := object.get(policy_inputs, "require_disposal_audit_events", false)

skip_reason := sprintf("Resource type %q is not an RDS database resource; this policy only applies to db-instance and db-cluster resources.", [resource_type]) if {
	not resource_type in {"db-instance", "db-cluster"}
}

cloudtrail_events contains event if {
	event := object.get(dynamic, "cloudtrail_events", [])[_]
}

cloudtrail_events contains event if {
	event := object.get(dynamic, "account_cloudtrail_events", [])[_]
}

deletion_event(event) if {
	object.get(event, "event_name", "") in {"DeleteDBInstance", "DeleteDBCluster"}
}

delete_event_skips_final_snapshot(event) if {
	deletion_event(event)
	raw := object.get(event, "cloudtrail_event", "")
	raw != ""
	payload := json.unmarshal(raw)
	params := object.get(payload, "requestParameters", {})
	object.get(params, "skipFinalSnapshot", false) == true
}

invalid_cloudtrail_json(event) if {
	deletion_event(event)
	raw := object.get(event, "cloudtrail_event", "")
	raw != ""
	not json.unmarshal(raw)
}

final_snapshot_identifier_present(params) if {
	object.get(params, "finalDBSnapshotIdentifier", "") != ""
}

final_snapshot_identifier_present(params) if {
	object.get(params, "finalDbSnapshotIdentifier", "") != ""
}

final_snapshot_identifier_present(params) if {
	object.get(params, "FinalDBSnapshotIdentifier", "") != ""
}

delete_event_missing_final_snapshot_identifier(event) if {
	deletion_event(event)
	raw := object.get(event, "cloudtrail_event", "")
	raw != ""
	payload := json.unmarshal(raw)
	params := object.get(payload, "requestParameters", {})
	object.get(params, "skipFinalSnapshot", false) != true
	not final_snapshot_identifier_present(params)
}

deletion_event_count := count({event | event := cloudtrail_events[_]; deletion_event(event)})
skipped_final_snapshot_count := count({event | event := cloudtrail_events[_]; delete_event_skips_final_snapshot(event)})
missing_final_snapshot_identifier_count := count({event | event := cloudtrail_events[_]; delete_event_missing_final_snapshot_identifier(event)})
invalid_json_count := count({event | event := cloudtrail_events[_]; invalid_cloudtrail_json(event)})

default deletion_audit_required := false

deletion_audit_required if {
	require_deletion_audit_events == true
}

deletion_audit_required if {
	require_disposal_audit_events == true
}

title := sprintf("Validate RDS deletion audit events for %s", [resource_id])
description := sprintf("RDS resource %s has %d deletion events in CloudTrail, %d deletion events that skipped the final snapshot, %d deletion events missing a final snapshot identifier, and %d events with invalid JSON; deletion audit required=%v.", [resource_id, deletion_event_count, skipped_final_snapshot_count, missing_final_snapshot_identifier_count, invalid_json_count, deletion_audit_required])

violation[{"id": "deletion_audit_event_missing"}] if {
	resource_type in {"db-instance", "db-cluster"}
	deletion_audit_required
	deletion_event_count == 0
}

violation[{"id": "deletion_event_skipped_final_snapshot"}] if {
	resource_type in {"db-instance", "db-cluster"}
	skipped_final_snapshot_count > 0
}

violation[{"id": "deletion_event_missing_final_snapshot_identifier"}] if {
	resource_type in {"db-instance", "db-cluster"}
	missing_final_snapshot_identifier_count > 0
}

violation[{"id": "deletion_event_invalid_cloudtrail_json"}] if {
	resource_type in {"db-instance", "db-cluster"}
	invalid_json_count > 0
}
