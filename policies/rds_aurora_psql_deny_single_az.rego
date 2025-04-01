package compliance_framework.template.aws._deny_single_az

# METADATA
# title: Ensure RDS instances are deployed across multiple availability zones
# description: Verifies that RDS instances are configured for high availability by being deployed across multiple availability zones.
# custom:
#   controls:
#     - SAMA_CSF_1.0
#     - SAMA_ITGF_1.0
#     - SAMA_RMG_1.0
#     - SAMA_CCF_1.0
#   schedule: "* * * * * *"

controls := [
    # SAMA Cyber Security Framework v1.0
    {
        "class": "SAMA_CSF_1.0",
        "control-id": "3.3.10", # Data Backup and Recoverability
        "statement-ids": [
            "1", # Define, approve, and implement a data backup management strategy.
            "2", # Ensure backup policies include considerations for backup frequency, storage, and security.
        ],
    },
    # SAMA IT Governance Framework v1.0
    {
        "class": "SAMA_ITGF_1.0",
        "control-id": "3.2.3", # Resilience and Availability
        "statement-ids": [
            "4", # Implement high-availability architectures to ensure business continuity.
        ],
    },
    # SAMA Risk Management Guidelines v1.0
    {
        "class": "SAMA_RMG_1.0",
        "control-id": "4.2.1", # Availability and Recovery
        "statement-ids": [
            "3", # Ensure availability strategies include multi-availability zone deployments.
        ],
    },
    # SAMA Cloud Computing Framework v1.0
    {
        "class": "SAMA_CCF_1.0",
        "control-id": "2.1.4", # Cloud Resilience
        "statement-ids": [
            "1", # Ensure cloud-based applications and databases have multi-AZ deployment for fault tolerance.
        ],
    },
]

violation[{
  "title": "RDS instance is not Multi-AZ",
}] if {
  not input.MultiAZ
}