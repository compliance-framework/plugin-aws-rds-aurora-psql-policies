package compliance_framework.template.aws._deny_no_automatic_backups

# METADATA
# title: Ensure automatic backups are enabled for AWS RDS databases
# description: Verifies that automatic backups are enabled to safeguard data integrity and availability for AWS RDS databases.
# custom:
#   controls:
#     - SAMA_CSF_1.0
#     - SAMA_ITGF_1.0
#     - SAMA_RMG_1.0
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
        "control-id": "2.4.5", # Data Retention and Backup
        "statement-ids": [
            "2", # Ensure that data retention and backup policies are defined and followed.
        ],
    },
    # SAMA Risk Management Guidelines v1.0
    {
        "class": "SAMA_RMG_1.0",
        "control-id": "4.2.3", # Backup and Disaster Recovery
        "statement-ids": [
            "1", # Ensure proper backup strategies are in place to minimize data loss and downtime.
        ],
    },
    # SAMA Cloud Computing Framework v1.0
    {
        "class": "SAMA_CCF_1.0",
        "control-id": "2.3.6", # Cloud Data Security and Backup
        "statement-ids": [
            "1", # Ensure that data backup procedures are implemented in the cloud environment.
        ],
    },
]

violation[{
  "title": "Automatic backups are not enabled",
}] if {
  input.BackupRetentionPeriod == 0
}