### CREATE NEW DEACTIVATED USERS IN ACTIVE DIRECTORY
# TODO Import user data from a CSV list.

# Import the Active Directory module in PowerShell.

Import-Module activedirectory

# Add new users to AD which are disabled. Remember to replace <variables>.

New-ADUser
	-Name "$username"
	-SamAccountName "$SamAccountName"
	-AccountPassword (ConvertTo-SecureString "$Password" -AsPlainText -Force)
	-DisplayName "$DisplayName"
	-Enabled $False

# Add the newly added users to a group. Remember to replace <variables>.

Add-ADGroupMember
	-Identity $GroupName
	-Members $CommaSeparatedMembers

### RESET ACTIVE DIRECTORY ACCOUNT PASSWORDS

Set-ADAccountPassword 
	-Identity $username 
	-Reset
	-NewPassword (ConvertTo-SecureString "$Password" -AsPlainText -Force)

### INTERROGATE AD

Get-ADPrincipalGroupMembership -Identity $username
Get-ADGroupMember -Identity $groupname

### REMEDIATE COMPROMISED ACCOUNTS

Remove-AdUser -Identity $username
Disable-AdAccount -Identity $username
