package compliance_framework.template.aws._deny_unencrypted_storage

# METADATA
# title: Ensure RDS storage encryption is enabled
# description: Verifies that the RDS instance storage encryption is enabled to protect sensitive data at rest.
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
        "control-id": "3.3.6", # Data Protection
        "statement-ids": [
            "1", # Ensure proper encryption for data at rest.
        ],
    },
    # SAMA IT Governance Framework v1.0
    {
        "class": "SAMA_ITGF_1.0",
        "control-id": "3.4.2", # Data Protection
        "statement-ids": [
            "3", # Ensure implementation of data encryption for sensitive data.
        ],
    },
    # SAMA Risk Management Guidelines v1.0
    {
        "class": "SAMA_RMG_1.0",
        "control-id": "5.3.1", # Data Protection and Security
        "statement-ids": [
            "1", # Ensure encryption mechanisms for protecting sensitive data.
        ],
    },
    # SAMA Cloud Computing Framework v1.0
    {
        "class": "SAMA_CCF_1.0",
        "control-id": "3.2.1", # Cloud Security
        "statement-ids": [
            "2", # Ensure that all sensitive data in the cloud is encrypted.
        ],
    },
]

violation[{
  "title": "RDS instance storage encryption is not enabled",
}] if {
  not input.StorageEncrypted
}