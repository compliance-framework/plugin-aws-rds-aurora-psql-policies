package compliance_framework.template.aws._deny_public_subnet

# METADATA
# title: Ensure RDS instances are not deployed in public subnets
# description: Verifies that RDS instances are not deployed in public subnets to maintain network security and integrity.
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
        "control-id": "3.3.8", # Infrastructure Security
        "statement-ids": [
            "6.e", # Segmentation of networks
        ],
        "control-link": "https://rulebook.sama.gov.sa/en/cyber-security-framework-2#infrastructure-security"
    },
    # SAMA IT Governance Framework v1.0
    {
        "class": "SAMA_ITGF_1.0",
        "control-id": "3.2.1", # Network Security and Access Control
        "statement-ids": [
            "3", # Implement network segmentation to isolate sensitive systems from public networks.
        ],
        "control-link": "https://rulebook.sama.gov.sa/en/it-governance-framework#network-security-and-access-control"
    },
    # SAMA Risk Management Guidelines v1.0
    {
        "class": "SAMA_RMG_1.0",
        "control-id": "3.2.4", # Network Security
        "statement-ids": [
            "1", # Ensure that systems and data are not exposed to unnecessary public networks.
        ],
        "control-link": "https://www.sama.gov.sa/en/RulesInstructions/RiskManagement#network-security"
    },
    # SAMA Cloud Computing Framework v1.0
    {
        "class": "SAMA_CCF_1.0",
        "control-id": "3.3.3", # Cloud Network Security
        "statement-ids": [
            "5", # Ensure private networking configurations for cloud-based services.
        ],
        "control-link": "https://www.sama.gov.sa/en/RulesInstructions/CloudComputing#cloud-network-security"
    },
]

violation[{
  "title": "RDS instance is deployed in a public subnet",
}] if {
  input.PubliclyAccessible
}
