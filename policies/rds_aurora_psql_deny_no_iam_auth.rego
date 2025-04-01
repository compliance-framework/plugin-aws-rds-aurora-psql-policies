package compliance_framework.template.aws._deny_no_iam_auth

# METADATA
# title: Ensure IAM database authentication is enabled
# description: Verifies that IAM database authentication is enabled for RDS instances to improve security by using IAM roles instead of traditional database credentials.
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
        "control-id": "3.3.5", # Identity and Access Management
        "statement-ids": [
            "5", # Enforce usage of IAM for authentication to improve security.
        ],
    },
    # SAMA IT Governance Framework v1.0
    {
        "class": "SAMA_ITGF_1.0",
        "control-id": "3.1.5", # Access Management
        "statement-ids": [
            "3", # Implement access controls that ensure only authorized users have access.
        ],
    },
    # SAMA Risk Management Guidelines v1.0
    {
        "class": "SAMA_RMG_1.0",
        "control-id": "2.1.2", # Authentication and Access Control
        "statement-ids": [
            "4", # Ensure that only authorized users and roles can access critical systems.
        ],
    },
    # SAMA Cloud Computing Framework v1.0
    {
        "class": "SAMA_CCF_1.0",
        "control-id": "3.2.1", # Cloud Authentication and Access Control
        "statement-ids": [
            "1", # Ensure cloud services implement strong authentication mechanisms.
        ],
    },
]

violation[{
  "title": "IAM database authentication is not enabled",
}] if {
  not input.IamDatabaseAuthenticationEnabled
}
