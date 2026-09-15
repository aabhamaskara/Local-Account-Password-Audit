# Local Account Password Audit Script

## What this is
A small PowerShell script I wrote to practice applying access-control and
least-privilege concepts from frameworks like NIST CSF. It scans the local
user accounts on a Windows machine and flags accounts that either:

- Have a password set to **never expire**, or
- Haven't had their password changed in **more than 90 days**

Sample output of deployed script uses anonymized account names. Real account identifiers were redacted before publishing, consistent with responsible disclosure practice.

## Why it matters
Weak password hygiene (when accounts create easy conditions for attackers because of weak or old passwords ) is a
common finding in real-world security and compliance audits. This script
is a small, hands-on way to practice thinking like a GRC/security analyst by starting to develop the mindset and process of:
- identifying a control (like password rotation)
- checking whether said control is being followed
- producing evidence (a report) that could support a real audit

## How to run it
1. Open PowerShell as Administrator.
2. Navigate to the folder containing `Audit-LocalAccounts.ps1`.
3. Run: `.\Audit-LocalAccounts.ps1`
4. Review the results printed to the screen, and check
   `AccountAuditResults.csv` in the same folder for the full saved report.

## What I'd do next to level up
- Add a check for accounts that are enabled but haven't logged in recently
- Map each finding directly to a specific NIST CSF subcategory
- Extend it to check domain accounts (Active Directory) instead of just
  local accounts
