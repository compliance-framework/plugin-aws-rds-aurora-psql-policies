package compliance_framework.rds_document_metric_policy_tests

compliant_input := {
	"resource": {"id": "db-1", "type": "db-instance"},
	"config": {
		"storage_encrypted": true,
		"kms_key_id": "arn:aws:kms:us-east-1:123456789012:key/key-id",
		"publicly_accessible": false,
		"vpc_security_groups": [{"VpcSecurityGroupId": "sg-123"}],
		"db_subnet_group": {"DBSubnetGroupName": "private-db"},
		"iam_database_authentication_enabled": true,
		"ssl_enforcement": {"default.postgres15": "1"},
		"ca_certificate_identifier": "rds-ca-rsa2048-g1",
		"deletion_protection": true,
		"backup_retention_period": 7,
		"latest_restorable_time": "2026-05-18T11:45:00Z",
		"multi_az": true,
		"enabled_cloudwatch_logs_exports": ["postgresql"],
		"monitoring_interval": 60,
	},
	"snapshots": [{
		"snapshot_identifier": "db-1-automated",
		"snapshot_type": "automated",
		"status": "available",
		"encrypted": true,
		"kms_key_id": "arn:aws:kms:us-east-1:123456789012:key/key-id",
		"snapshot_create_time": "2026-05-18T10:30:00Z",
		"shared_accounts": [],
		"public": false,
	}],
	"dynamic": {
		"cloudtrail_events": [],
		"account_cloudtrail_events": [],
		"rds_events": [],
		"cloudwatch_metrics": {},
	},
	"collection": {"collected_at": "2026-05-18T12:00:00Z"},
	"policy_inputs": {
		"minimum_backup_retention_days": 7,
		"required_log_exports": ["postgresql"],
	},
}

compliant_snapshot_input := {
	"resource": {"id": "db-1-latest-automated", "type": "db-snapshot"},
	"config": {
		"snapshot_identifier": "db-1-latest-automated",
		"snapshot_type": "automated",
		"snapshot_create_time": "2026-05-18T10:30:00Z",
		"status": "available",
		"encrypted": true,
		"kms_key_id": "arn:aws:kms:us-east-1:123456789012:key/key-id",
		"shared_accounts": [],
		"public": false,
	},
	"policy_inputs": {
		"approved_snapshot_accounts": [],
	},
}

test_compliant_input_has_no_document_policy_violations if {
	count(data.compliance_framework.rds_database_storage_encryption.violation) == 0 with input as compliant_input
	count(data.compliance_framework.rds_network_boundary.violation) == 0 with input as compliant_input
	count(data.compliance_framework.rds_iam_database_auth.violation) == 0 with input as compliant_input
	count(data.compliance_framework.rds_tls_enforcement.violation) == 0 with input as compliant_input
	count(data.compliance_framework.rds_deletion_protection.violation) == 0 with input as compliant_input
	count(data.compliance_framework.rds_backup_retention.violation) == 0 with input as compliant_input
	count(data.compliance_framework.rds_snapshot_coverage.violation) == 0 with input as compliant_input
	count(data.compliance_framework.rds_pitr_freshness.violation) == 0 with input as compliant_input
	count(data.compliance_framework.rds_multi_az_redundancy.violation) == 0 with input as compliant_input
	count(data.compliance_framework.rds_snapshot_restore_access.violation) == 0 with input as compliant_input
	count(data.compliance_framework.rds_log_exports.violation) == 0 with input as compliant_input
	count(data.compliance_framework.rds_capacity_monitoring.violation) == 0 with input as compliant_input
	count(data.compliance_framework.rds_backup_restore_events.violation) == 0 with input as compliant_input
	count(data.compliance_framework.rds_management_audit_events.violation) == 0 with input as compliant_input
}

test_compliant_snapshot_input_has_no_snapshot_policy_violations if {
	count(data.compliance_framework.rds_snapshot_encryption.violation) == 0 with input as compliant_snapshot_input
	count(data.compliance_framework.rds_snapshot_restore_access.violation) == 0 with input as compliant_snapshot_input
	count(data.compliance_framework.rds_snapshot_status.violation) == 0 with input as compliant_snapshot_input
}

test_database_policy_skips_snapshot_resource if {
	reason := data.compliance_framework.rds_log_exports.skip_reason with input as compliant_snapshot_input
	contains(reason, "db-snapshot")
}

test_snapshot_policy_skips_database_resource if {
	reason := data.compliance_framework.rds_snapshot_encryption.skip_reason with input as compliant_input
	contains(reason, "db-instance")
}

test_network_boundary_flags_public_database if {
	test_input := object.union_n([compliant_input, {"config": object.union(compliant_input.config, {"publicly_accessible": true})}])
	violations := data.compliance_framework.rds_network_boundary.violation with input as test_input
	violations[{"id": "database_publicly_accessible"}]
}

test_backup_restore_events_flags_restore_event_when_required if {
	test_input := object.union_n([compliant_input, {"policy_inputs": object.union(compliant_input.policy_inputs, {"require_restore_events": true})}])
	violations := data.compliance_framework.rds_backup_restore_events.violation with input as test_input
	violations[{"id": "restore_event_missing"}]
}

test_pitr_freshness_flags_stale_pitr if {
	test_input := object.union_n([compliant_input, {"config": object.union(compliant_input.config, {"latest_restorable_time": "2026-05-16T12:00:00Z"})}])
	violations := data.compliance_framework.rds_pitr_freshness.violation with input as test_input
	violations[{"id": "latest_restorable_time_stale"}]
}

test_snapshot_restore_access_flags_public_snapshot if {
	test_input := object.union_n([compliant_snapshot_input, {"config": object.union(compliant_snapshot_input.config, {"public": true})}])
	violations := data.compliance_framework.rds_snapshot_restore_access.violation with input as test_input
	violations[{"id": "snapshot_public"}]
}

test_snapshot_policies_ignore_database_parent_snapshot_list if {
	older_public_unencrypted := object.union(compliant_input.snapshots[0], {
		"snapshot_identifier": "db-1-manual-older",
		"snapshot_type": "manual",
		"snapshot_create_time": "2026-05-17T10:30:00Z",
		"encrypted": false,
		"kms_key_id": "",
		"public": true,
	})
	test_input := object.union_n([compliant_input, {"snapshots": [older_public_unencrypted]}])
	count(data.compliance_framework.rds_snapshot_encryption.violation) == 0 with input as test_input
	count(data.compliance_framework.rds_snapshot_restore_access.violation) == 0 with input as test_input
	count(data.compliance_framework.rds_snapshot_status.violation) == 0 with input as test_input
}

test_snapshot_encryption_flags_current_unencrypted_snapshot if {
	test_input := object.union_n([compliant_snapshot_input, {"config": object.union(compliant_snapshot_input.config, {
		"encrypted": false,
		"kms_key_id": "",
	})}])
	violations := data.compliance_framework.rds_snapshot_encryption.violation with input as test_input
	violations[{"id": "snapshot_unencrypted"}]
}

test_snapshot_status_flags_current_unavailable_snapshot if {
	test_input := object.union_n([compliant_snapshot_input, {"config": object.union(compliant_snapshot_input.config, {"status": "failed"})}])
	violations := data.compliance_framework.rds_snapshot_status.violation with input as test_input
	violations[{"id": "snapshot_not_available"}]
}

test_snapshot_coverage_flags_missing_snapshot_history if {
	test_input := object.union_n([compliant_input, {"snapshots": []}])
	violations := data.compliance_framework.rds_snapshot_coverage.violation with input as test_input
	violations[{"id": "snapshot_history_missing"}]
}

test_snapshot_coverage_flags_missing_automated_snapshot_when_required if {
	manual_snapshot := object.union(compliant_input.snapshots[0], {"snapshot_type": "manual"})
	test_input := object.union_n([compliant_input, {
		"snapshots": [manual_snapshot],
		"policy_inputs": object.union(compliant_input.policy_inputs, {"require_automated_snapshot": true}),
	}])
	violations := data.compliance_framework.rds_snapshot_coverage.violation with input as test_input
	violations[{"id": "automated_snapshot_missing"}]
}

test_deletion_audit_flags_missing_final_snapshot_identifier if {
	deletion_event := {
		"event_name": "DeleteDBInstance",
		"cloudtrail_event": "{\"requestParameters\":{\"skipFinalSnapshot\":false}}",
	}
	test_input := object.union_n([compliant_input, {"dynamic": object.union(compliant_input.dynamic, {"cloudtrail_events": [deletion_event]})}])
	violations := data.compliance_framework.rds_deletion_audit_events.violation with input as test_input
	violations[{"id": "deletion_event_missing_final_snapshot_identifier"}]
}

test_log_exports_flags_missing_required_logs if {
	test_input := object.union_n([compliant_input, {"config": object.union(compliant_input.config, {"enabled_cloudwatch_logs_exports": []})}])
	violations := data.compliance_framework.rds_log_exports.violation with input as test_input
	violations[{"id": "required_log_exports_missing"}]
}
