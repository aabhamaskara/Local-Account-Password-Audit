# =====================================================================
# Audit-LocalAccounts.ps1
#
# What is this for:
#   This script checks the local user accounts on a Windows computer and flags any that could be a security risk because of how their
#   password is set up. Specifically, what the script is designed to be looking for are:
#     1. Accounts where the password is set to NEVER expire
#     2. Accounts whose password hasn't been changed in ___ days (I used 90 days as the cutoff since that is a common standard used 
#         in many compliance frameworks)
#
# Why is this important:
#   Compliance frameworks like NIST CSF ask organizations to enforce least privilege principles and strong access control.
#   Typically, step one of that enforcement is making sure that accounts do not have passwords that old (either because they
#   were not changed ever since they were created or simply not changed in the threshold for the number of days set by the
#   organization), weak, or set to never expire. This step in simple but incredibly important because they provide gateways
#   for attackers to compromise and stay hidden inside of these easy to access accounts.

# =====================================================================

# Step 1: Get every local user account on this computer. Get-LocalUser is a built-in PowerShell command that lists accounts.
$allAccounts = Get-LocalUser

# Step 2: Create an empty list where we'll collect any accounts that could be potential attack vectors.
$flaggedAccounts = @()

# Step 3: Set our threshold for what is considered too old of a password making sure to set it as ____ day from TODAY. 90 days is a very 
#         common baseline in security policies
$daysThreshold = 90
$today = Get-Date

# Step 4: Go through each account one at a time and check it with the conditions we set.
foreach ($account in $allAccounts) {

    # Create an empty list that will hold the reason(s) we flag an account, if any.
    $reasons = @()

    # Check #1: Does this account's password NEVER expire?
    if ($account.PasswordExpires -eq $null -and $account.Enabled -eq $true) {
        $reasons += "Password never expires"
    }

    # Check #2: Was the password last changed more than 90 days ago?
    if ($account.PasswordLastSet -ne $null) {
        $daysSinceChange = ($today - $account.PasswordLastSet).Days
        if ($daysSinceChange -gt $daysThreshold) {
            $reasons += "Password not changed in $daysSinceChange days"
        }
    }

    # If we found any reasons to flag this account, save it to the list we created.
    if ($reasons.Count -gt 0) {
        $flaggedAccounts += [PSCustomObject]@{
            AccountName      = $account.Name
            Enabled          = $account.Enabled
            PasswordLastSet  = $account.PasswordLastSet
            Reason           = ($reasons -join "; ")
        }
    }
}

# Step 5: Show the results on screen so you can see them right away.
Write-Host ""
Write-Host "===== Local Account Password Audit =====" -ForegroundColor Cyan
Write-Host "Checked $($allAccounts.Count) account(s) on $($env:COMPUTERNAME)"
Write-Host ""

if ($flaggedAccounts.Count -eq 0) {
    Write-Host "No risky accounts found. Nice and tidy!" -ForegroundColor Green
} else {
    Write-Host "$($flaggedAccounts.Count) account(s) flagged for review:" -ForegroundColor Yellow
    $flaggedAccounts | Format-Table -AutoSize
}

# Step 6: Save the results to a CSV file so you have a saved record.
$outputPath = "$PSScriptRoot\AccountAuditResults.csv"
$flaggedAccounts | Export-Csv -Path $outputPath -NoTypeInformation

Write-Host ""
Write-Host "Full results saved to: $outputPath" -ForegroundColor Cyan
