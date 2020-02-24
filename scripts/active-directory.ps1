# This script is used to create new deactivated users in Active Directory.
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
