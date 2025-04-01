package compliance_framework.template.aws._deny_no_auto_minor_upgrade

# METADATA
# title: Ensure auto minor version upgrades are enabled
# description: Verifies that auto minor version upgrades are enabled for supported AWS services to ensure timely updates and patches.
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
            "2", # Ensure proper update management and patching.
        ],
    },
    # SAMA IT Governance Framework v1.0
    {
        "class": "SAMA_ITGF_1.0",
        "control-id": "4.1.2", # Patch Management
        "statement-ids": [
            "1", # Ensure patching processes are defined and timely applied.
        ],
    },
    # SAMA Risk Management Guidelines v1.0
    {
        "class": "SAMA_RMG_1.0",
        "control-id": "3.5.4", # Vulnerability and Patch Management
        "statement-ids": [
            "2", # Ensure vulnerabilities are mitigated through timely patching.
        ],
    },
    # SAMA Cloud Computing Framework v1.0
    {
        "class": "SAMA_CCF_1.0",
        "control-id": "2.2.3", # Cloud Patch and Update Management
        "statement-ids": [
            "1", # Ensure that cloud services are patched with the latest updates and patches.
        ],
    },
]

violation[{
  "title": "Auto minor version upgrades are disabled",
}] if {
  not input.AutoMinorVersionUpgrade
}
