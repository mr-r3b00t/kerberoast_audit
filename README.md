# Get-SPNPrivilegedUsers

<p align="center">
  <img src="https://img.shields.io/badge/PowerShell-5.0%2B-blue.svg" alt="PowerShell 5.0+">
  <img src="https://img.shields.io/badge/Platform-Windows-lightgrey.svg" alt="Windows">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="MIT License">
  <img src="https://img.shields.io/badge/AD%20Module-Required-orange.svg" alt="AD Module Required">
</p>

A PowerShell security auditing tool that identifies Active Directory users with Service Principal Names (SPNs) who are members of high-privilege groups. Optionally performs Kerberoasting to extract service ticket hashes for offline password strength testing.

## ⚠️ Disclaimer

> **This tool is intended for AUTHORIZED SECURITY TESTING and EDUCATIONAL PURPOSES ONLY.**
>
> - You must have explicit written authorization before running this tool
> - Unauthorized use may violate laws including the Computer Fraud and Abuse Act (CFAA), GDPR, and similar legislation
> - This tool is provided "AS IS" without warranty of any kind
> - **YOU USE THIS TOOL ENTIRELY AT YOUR OWN RISK**
>
> The authors are not responsible for any misuse or damage caused by this tool.

---

## 🎯 Purpose

Users with SPNs configured and membership in privileged groups are high-value targets for **Kerberoasting attacks**. If an attacker can crack the service ticket hash, they gain access to a privileged account.

This tool helps security teams:
- **Identify** privileged accounts with SPNs (Kerberoastable accounts)
- **Assess** password strength by extracting hashes for offline cracking
- **Detect** weak RC4 encryption usage
- **Audit** both direct and nested group memberships

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **Privileged Group Detection** | Checks 12 high-privilege AD groups |
| 🔄 **Recursive Membership** | Uses `LDAP_MATCHING_RULE_IN_CHAIN` for nested group detection |
| 🎟️ **Kerberoasting** | Requests TGS tickets and extracts hashes |
| ⚠️ **RC4 Warnings** | Alerts on weak RC4-HMAC encryption usage |
| 📊 **Multiple Export Formats** | CSV reports and hashcat/john compatible hash files |
| 🛡️ **Authorization Prompts** | Interactive confirmation before extracting hashes |
| 📈 **Risk Ratings** | Categorizes groups as CRITICAL, HIGH, or MEDIUM risk |

### Privileged Groups Checked

| Group | Risk Level |
|-------|------------|
| Domain Admins | 🔴 CRITICAL |
| Enterprise Admins | 🔴 CRITICAL |
| Schema Admins | 🔴 CRITICAL |
| Administrators (Built-in) | 🔴 CRITICAL |
| Account Operators | 🟠 HIGH |
| Server Operators | 🟠 HIGH |
| Backup Operators | 🟠 HIGH |
| DnsAdmins | 🟠 HIGH |
| Key Admins | 🟠 HIGH |
| Enterprise Key Admins | 🟠 HIGH |
| Print Operators | 🟡 MEDIUM |
| Group Policy Creator Owners | 🟡 MEDIUM |

---

## 📋 Requirements

- **PowerShell 5.0** or later
- **Active Directory PowerShell Module** (RSAT)
- Domain-joined machine or network access to a DC
- Appropriate permissions to query AD

### Installing RSAT (if needed)

```powershell
# Windows 10/11
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0

# Windows Server
Install-WindowsFeature -Name RSAT-AD-PowerShell
```

---

## 🚀 Usage

### Basic Enumeration (No Ticket Requests)

```powershell
.\Get-SPNPrivilegedUsers.ps1
```

### Request Tickets and Extract Hashes

```powershell
.\Get-SPNPrivilegedUsers.ps1 -RequestTicket
```

### Export Hashes for Cracking

```powershell
.\Get-SPNPrivilegedUsers.ps1 -RequestTicket -ExportHashes "C:\Audit\hashes.txt"
```

### Full Audit with All Exports

```powershell
.\Get-SPNPrivilegedUsers.ps1 -RequestTicket -ExportHashes "C:\Audit\hashes.txt" -ExportCsv "C:\Audit\report.csv"
```

### Query Specific Domain Controller

```powershell
.\Get-SPNPrivilegedUsers.ps1 -Server "DC01.contoso.com" -RequestTicket
```

### Limit Search Scope

```powershell
.\Get-SPNPrivilegedUsers.ps1 -SearchBase "OU=ServiceAccounts,DC=contoso,DC=com"
```

---

## 📝 Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `-Server` | String | Domain controller to query (optional) |
| `-SearchBase` | String | AD path to limit search scope (optional) |
| `-RequestTicket` | Switch | Request Kerberos tickets and extract hashes |
| `-ExportCsv` | String | Path to export CSV report |
| `-ExportHashes` | String | Path to export hashes (hashcat/john format) |

---

## 📤 Output

### Console Output

```
========================================
  SPN Users with Privileged Access
========================================

┌─────────────────────────────────────────────────────────────────┐
│  DISCLAIMER: For authorized security testing only.             │
│  Ensure you have written permission to test this environment.  │
│  Unauthorized use may violate applicable laws.                 │
│  USE AT YOUR OWN RISK. See Get-Help for full disclaimer.       │
└─────────────────────────────────────────────────────────────────┘

[*] Domain: contoso.com
[*] Forest: contoso.com
[*] Enumerating privileged groups...
[*] Found 12 privileged groups to check
[*] Searching for users with SPNs...
[*] Found 15 user(s) with SPNs
[*] Checking privileged group memberships...

[!] Found 3 privileged user(s) with SPNs.

    Do you want to request Kerberos tickets and extract hashes? (Y/N): Y

─────────────────────────────────────────
User: svc_backup
  Display Name:      Backup Service Account
  Enabled:           True
  Privileged Groups: 2 group(s)
    Direct:          Backup Operators
    Nested:          Domain Admins
  Password Set:      01/15/2023 10:30:00
  SPNs:              MSSQLSvc/SQL01.contoso.com:1433

  [KERBEROS TICKET]
  Hash Type:         RC4-HMAC (NT Hash) [WEAK]
  Hashcat Mode:      13100
  Hash:              $krb5tgs$23$*svc_backup$CONTOSO$*$a1b2c3d4...
─────────────────────────────────────────
```

### RC4 Warning Box

```
╔══════════════════════════════════════════════════════════════╗
║  RC4-HMAC SECURITY WARNING                                   ║
╠══════════════════════════════════════════════════════════════╣
║  3 account(s) are using RC4-HMAC (etype 23)                  ║
║                                                              ║
║  RISKS:                                                      ║
║  • RC4 uses the NT hash directly as the key                  ║
║  • Significantly faster to crack than AES                    ║
║  • Deprecated by Microsoft since 2013                        ║
║                                                              ║
║  REMEDIATION:                                                ║
║  1. Set 'Network security: Configure encryption types        ║
║     allowed for Kerberos' to AES128/AES256 only via GPO     ║
║  2. Update account msDS-SupportedEncryptionTypes to 0x18    ║
║  3. Reset passwords after enabling AES                       ║
║  4. Monitor Event ID 4769 for RC4 ticket requests           ║
╚══════════════════════════════════════════════════════════════╝
```

### CSV Export Fields

| Field | Description |
|-------|-------------|
| SamAccountName | Account username |
| DisplayName | Display name |
| Enabled | Account enabled status |
| PrivilegedGroups | All privileged group memberships |
| DirectMemberships | Direct group memberships |
| NestedMemberships | Nested/inherited memberships |
| PrivilegedGroupCount | Number of privileged groups |
| AdminCount | AD AdminCount attribute |
| ServicePrincipalNames | All SPNs on the account |
| PasswordLastSet | When password was last changed |
| LastLogonDate | Last logon timestamp |
| Description | Account description |
| DistinguishedName | Full AD path |
| HashType | Encryption type (if requested) |
| HashcatMode | Hashcat mode number |
| UsingRC4 | Boolean - using weak RC4 |
| Hash | Full hash (if requested) |

---

## 🔓 Cracking Extracted Hashes

### Hashcat

```bash
# RC4-HMAC (etype 23) - Mode 13100
hashcat -m 13100 hashes.txt wordlist.txt

# AES256-CTS-HMAC-SHA1-96 (etype 18) - Mode 19700
hashcat -m 19700 hashes.txt wordlist.txt

# AES128-CTS-HMAC-SHA1-96 (etype 17) - Mode 19600
hashcat -m 19600 hashes.txt wordlist.txt

# With rules
hashcat -m 13100 hashes.txt wordlist.txt -r rules/best64.rule
```

### John the Ripper

```bash
john --format=krb5tgs hashes.txt --wordlist=wordlist.txt
```

---

## 🛡️ Remediation Recommendations

If this tool identifies vulnerable accounts, consider the following remediation steps:

### Immediate Actions

1. **Remove unnecessary SPNs** from privileged accounts
2. **Implement strong passwords** (25+ characters) for all SPN accounts
3. **Disable RC4** encryption for Kerberos via Group Policy

### Long-term Improvements

4. **Use Group Managed Service Accounts (gMSA)** where possible
5. **Add privileged accounts to Protected Users** security group
6. **Implement tiered administration model** (PAW/Tier 0)
7. **Monitor Event ID 4769** for Kerberoasting attempts
8. **Review nested group memberships** regularly
9. **Enable AES-only encryption** for Kerberos:
   ```
   Computer Configuration → Policies → Windows Settings → 
   Security Settings → Local Policies → Security Options →
   "Network security: Configure encryption types allowed for Kerberos"
   → Enable only AES128 and AES256
   ```

---

## 📊 Hash Types Reference

| EType | Algorithm | Hashcat Mode | Relative Strength |
|-------|-----------|--------------|-------------------|
| 23 | RC4-HMAC | 13100 | ⚠️ Weak (Deprecated) |
| 17 | AES128-CTS-HMAC-SHA1-96 | 19600 | ✅ Strong |
| 18 | AES256-CTS-HMAC-SHA1-96 | 19700 | ✅ Strongest |

---

## 🔍 How It Works

1. **Enumerate SPNs**: Queries AD for all user accounts with `servicePrincipalName` attribute set
2. **Check Group Membership**: Uses `LDAP_MATCHING_RULE_IN_CHAIN` (OID 1.2.840.113556.1.4.1941) for efficient recursive group membership checking
3. **Request Tickets** (optional): Uses `System.IdentityModel.Tokens.KerberosRequestorSecurityToken` to request TGS tickets
4. **Parse Tickets**: Extracts encryption type and cipher from ASN.1 DER-encoded ticket
5. **Format Hashes**: Outputs in hashcat/john compatible `$krb5tgs$` format

---

## 📚 References

- [Kerberoasting - MITRE ATT&CK T1558.003](https://attack.mitre.org/techniques/T1558/003/)
- [Microsoft - Kerberos Encryption Types](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos)
- [Hashcat - Kerberos 5 TGS-REP](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [ADSecurity - Kerberoasting](https://adsecurity.org/?p=2293)

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 🙏 Acknowledgments

- Inspired by various Kerberoasting tools in the security community
- Thanks to all contributors and testers

---

<p align="center">
  <b>Remember: Always obtain proper authorization before security testing!</b>
</p>
