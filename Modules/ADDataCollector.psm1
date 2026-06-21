#Requires -Version 5.1
<#
.SYNOPSIS
    Active Directory data collection module for the AD Attack Path Analysis Platform.
    Collects comprehensive AD object data, ACLs, delegations, and security configurations.
#>

Import-Module ActiveDirectory -ErrorAction Stop

#region Main Collection Entry Point

function Invoke-ADDataCollection {
    [CmdletBinding()]
    param(
        [hashtable]$Config,
        [System.Management.Automation.PSCredential]$Credential
    )

    # ── Build base AD parameter hashtable ────────────────────────────────────
    $adParams = @{ ErrorAction = 'Stop' }
    if ($Credential) { $adParams.Credential = $Credential }

    # ── Determine target Domain Controller ────────────────────────────────────
    # Priority: 1) Config explicit DC list  2) PDC Emulator (auto)  3) KDC from DNS
    $targetServer = Resolve-TargetDomainController -Config $Config -Credential $Credential
    if ($targetServer) {
        $adParams.Server = $targetServer
        Write-Log "Targeting Domain Controller: $targetServer" -Level INFO -Component ADCollector
    }

    try {
        $domain = Get-ADDomain @adParams
        $forest = Get-ADForest @adParams
    } catch {
        Write-Log "Failed to connect to Active Directory: $_" -Level CRITICAL -Component ADCollector
        throw
    }

    # If we auto-selected, confirm the PDC emulator is being used
    if (-not $targetServer) {
        # Fall back to the PDC emulator of the discovered domain for consistency
        try {
            $adParams.Server = $domain.PDCEmulator
            Write-Log "Auto-selected PDC Emulator: $($domain.PDCEmulator)" -Level INFO -Component ADCollector
        } catch {
            Write-Log "Could not resolve PDC Emulator — using default DC from DNS." -Level WARNING -Component ADCollector
        }
    }

    Write-Log "Connected to domain: $($domain.DNSRoot) via $($adParams.Server)" -Level INFO -Component ADCollector

    $result = [ordered]@{
        CollectionTime        = Get-Date -Format 'o'
        Domain                = $null
        Forest                = $null
        Users                 = @()
        Groups                = @()
        Computers             = @()
        ServiceAccounts       = @()
        ManagedServiceAccounts= @()
        OrganizationalUnits   = @()
        GroupPolicies         = @()
        DomainControllers     = @()
        Trusts                = @()
        PrivilegedGroups      = @()
        ACLFindings           = @()
        DelegationFindings    = @()
        KerberoastableAccounts= @()
        ASREPRoastableAccounts= @()
        SIDHistoryAccounts    = @()
        StaleAccounts         = @()
        DormantPrivAccounts   = @()
        AdminCountAccounts    = @()
        PasswordFindings      = @()
        ProtectedUsersMembers = @()
        FineGrainedPolicies   = @()
        ShadowAdmins          = @()
        Tier0Objects          = @()
        Tier1Objects          = @()
        DCSyncAccounts        = @()
        OrphanedSIDs          = @()
        CircularGroups        = @()
    }

    $result.Domain = Get-DomainInfo -Domain $domain -ADParams $adParams
    $result.Forest = Get-ForestInfo -Forest $forest

    Write-Log "Collecting users..." -Level INFO -Component ADCollector
    $result.Users = Get-ADUsersData -ADParams $adParams -Config $Config

    Write-Log "Collecting groups..." -Level INFO -Component ADCollector
    $result.Groups = Get-ADGroupsData -ADParams $adParams -Config $Config

    Write-Log "Collecting computers..." -Level INFO -Component ADCollector
    $result.Computers = Get-ADComputersData -ADParams $adParams

    Write-Log "Collecting service accounts..." -Level INFO -Component ADCollector
    $result.ServiceAccounts        = Get-ServiceAccountsData -ADParams $adParams
    $result.ManagedServiceAccounts = Get-ManagedServiceAccountsData -ADParams $adParams

    Write-Log "Collecting OUs and GPOs..." -Level INFO -Component ADCollector
    $result.OrganizationalUnits = Get-OUData -ADParams $adParams
    $result.GroupPolicies       = Get-GPOData -ADParams $adParams

    Write-Log "Collecting domain controllers and trusts..." -Level INFO -Component ADCollector
    $result.DomainControllers = Get-DomainControllerData -ADParams $adParams
    $result.Trusts            = Get-TrustData -ADParams $adParams

    Write-Log "Analyzing privileged groups..." -Level INFO -Component ADCollector
    $result.PrivilegedGroups = Get-PrivilegedGroupsData -ADParams $adParams -Config $Config

    Write-Log "Analyzing ACLs and delegations..." -Level INFO -Component ADCollector
    if ($Config.Analysis.EnableACLAnalysis) {
        $result.ACLFindings        = Get-ACLFindings -ADParams $adParams -Domain $domain
        $result.DelegationFindings = Get-DelegationFindings -ADParams $adParams
    }

    Write-Log "Analyzing attack surface accounts..." -Level INFO -Component ADCollector
    $result.KerberoastableAccounts  = Get-KerberoastableAccounts -ADParams $adParams
    $result.ASREPRoastableAccounts  = Get-ASREPRoastableAccounts -ADParams $adParams
    $result.SIDHistoryAccounts      = Get-SIDHistoryAccounts -ADParams $adParams
    $result.AdminCountAccounts      = Get-AdminCountAccounts -ADParams $adParams
    $result.PasswordFindings        = Get-PasswordFindings -ADParams $adParams
    $result.ProtectedUsersMembers   = Get-ProtectedUsersData -ADParams $adParams
    $result.FineGrainedPolicies     = Get-FineGrainedPasswordPolicies -ADParams $adParams
    $result.OrphanedSIDs            = Get-OrphanedSIDs -ADParams $adParams -Domain $domain

    Write-Log "Analyzing stale and dormant accounts..." -Level INFO -Component ADCollector
    $staleDays   = $Config.Analysis.StaleAccountDays
    $dormantDays = $Config.Analysis.DormantPrivilegedAccountDays
    $result.StaleAccounts        = Get-StaleAccounts -ADParams $adParams -StaleDays $staleDays
    $result.DormantPrivAccounts  = Get-DormantPrivilegedAccounts -ADParams $adParams -DormantDays $dormantDays -Config $Config

    Write-Log "Analyzing shadow admins and DCSync..." -Level INFO -Component ADCollector
    if ($Config.Analysis.EnableShadowAdmins) {
        $result.ShadowAdmins = Get-ShadowAdmins -ADParams $adParams -Domain $domain
    }
    if ($Config.Analysis.EnableDCSync) {
        $result.DCSyncAccounts = Get-DCSyncAccounts -ADParams $adParams -Domain $domain
    }

    Write-Log "Classifying Tier-0 and Tier-1 objects..." -Level INFO -Component ADCollector
    $result.Tier0Objects   = Get-Tier0Objects -ADParams $adParams -Config $Config
    $result.Tier1Objects   = Get-Tier1Objects -ADParams $adParams -Config $Config

    Write-Log "Detecting circular group memberships..." -Level INFO -Component ADCollector
    $result.CircularGroups = Find-CircularGroupMemberships -Groups $result.Groups

    Write-Log "Data collection complete." -Level SUCCESS -Component ADCollector
    return $result
}

#endregion

#region Domain / Forest

function Get-DomainInfo {
    param($Domain, $ADParams)
    [ordered]@{
        Name                  = $Domain.Name
        DNSRoot               = $Domain.DNSRoot
        NetBIOSName           = $Domain.NetBIOSName
        DomainSID             = $Domain.DomainSID.Value
        DomainMode            = $Domain.DomainMode.ToString()
        PDCEmulator           = $Domain.PDCEmulator
        RIDMaster             = $Domain.RIDMaster
        InfrastructureMaster  = $Domain.InfrastructureMaster
        DistinguishedName     = $Domain.DistinguishedName
        ParentDomain          = $Domain.ParentDomain
        ChildDomains          = @($Domain.ChildDomains)
    }
}

function Get-ForestInfo {
    param($Forest)
    [ordered]@{
        Name            = $Forest.Name
        ForestMode      = $Forest.ForestMode.ToString()
        SchemaMaster    = $Forest.SchemaMaster
        DomainNamingMaster = $Forest.DomainNamingMaster
        RootDomain      = $Forest.RootDomain
        Domains         = @($Forest.Domains)
        GlobalCatalogs  = @($Forest.GlobalCatalogs)
    }
}

#endregion

#region Users

function Get-ADUsersData {
    param($ADParams, $Config)

    $properties = @(
        'SamAccountName','UserPrincipalName','DistinguishedName','DisplayName',
        'Enabled','PasswordLastSet','PasswordNeverExpires','PasswordNotRequired',
        'PasswordExpired','LastLogonDate','LastLogon','AdminCount','SIDHistory',
        'ServicePrincipalName','TrustedForDelegation','TrustedToAuthForDelegation',
        'AllowReversiblePasswordEncryption','DoesNotRequirePreAuth','PrimaryGroup',
        'MemberOf','ObjectSID','ObjectClass','WhenCreated','WhenChanged',
        'Description','msDS-SupportedEncryptionTypes','msDS-AllowedToDelegateTo',
        'msDS-AllowedToActOnBehalfOfOtherIdentity','SmartcardLogonRequired',
        'AccountExpirationDate','LockedOut','BadPwdCount','Modified','Created'
    )

    try {
        $users = Get-ADUser -Filter * -Properties $properties @ADParams
        $userList = foreach ($u in $users) {
            if (-not $Config.Analysis.IncludeDisabledAccounts -and -not $u.Enabled) { continue }
            [ordered]@{
                SamAccountName              = $u.SamAccountName
                UserPrincipalName           = $u.UserPrincipalName
                DistinguishedName           = $u.DistinguishedName
                DisplayName                 = $u.DisplayName
                Enabled                     = $u.Enabled
                PasswordLastSet             = $u.PasswordLastSet
                PasswordNeverExpires        = $u.PasswordNeverExpires
                PasswordNotRequired         = $u.PasswordNotRequired
                PasswordExpired             = $u.PasswordExpired
                LastLogonDate               = $u.LastLogonDate
                AdminCount                  = $u.AdminCount
                HasSIDHistory               = ($null -ne $u.SIDHistory -and $u.SIDHistory.Count -gt 0)
                SIDHistoryValues            = @($u.SIDHistory | ForEach-Object { $_.Value })
                ServicePrincipalNames       = @($u.ServicePrincipalName)
                HasSPN                      = ($null -ne $u.ServicePrincipalName -and $u.ServicePrincipalName.Count -gt 0)
                TrustedForDelegation        = $u.TrustedForDelegation
                TrustedToAuthForDelegation  = $u.TrustedToAuthForDelegation
                AllowReversiblePassword     = $u.AllowReversiblePasswordEncryption
                DoesNotRequirePreAuth       = $u.DoesNotRequirePreAuth
                MemberOf                    = @($u.MemberOf)
                ObjectSID                   = $u.ObjectSID.Value
                WhenCreated                 = $u.WhenCreated
                WhenChanged                 = $u.WhenChanged
                Description                 = $u.Description
                AllowedToDelegateTo         = @($u.'msDS-AllowedToDelegateTo')
                SmartcardRequired           = $u.SmartcardLogonRequired
                AccountExpires              = $u.AccountExpirationDate
                LockedOut                   = $u.LockedOut
                BadPwdCount                 = $u.BadPwdCount
            }
        }
        return @($userList)
    } catch {
        Write-Log "Error collecting users: $_" -Level ERROR -Component ADCollector
        return @()
    }
}

#endregion

#region Groups

function Get-ADGroupsData {
    param($ADParams, $Config)

    $properties = @(
        'SamAccountName','DistinguishedName','Description','GroupCategory',
        'GroupScope','ManagedBy','Members','MemberOf','ObjectSID','WhenCreated',
        'WhenChanged','AdminCount','Mail'
    )

    try {
        $groups = Get-ADGroup -Filter * -Properties $properties @ADParams
        $groupList = foreach ($g in $groups) {
            [ordered]@{
                SamAccountName    = $g.SamAccountName
                DistinguishedName = $g.DistinguishedName
                Description       = $g.Description
                GroupCategory     = $g.GroupCategory.ToString()
                GroupScope        = $g.GroupScope.ToString()
                ManagedBy         = $g.ManagedBy
                Members           = @($g.Members)
                MemberOf          = @($g.MemberOf)
                ObjectSID         = $g.ObjectSID.Value
                WhenCreated       = $g.WhenCreated
                WhenChanged       = $g.WhenChanged
                AdminCount        = $g.AdminCount
                IsPrivileged      = $Config.Analysis.PrivilegedGroups -contains $g.SamAccountName
                IsTier0           = $Config.Analysis.Tier0Groups -contains $g.SamAccountName
            }
        }
        return @($groupList)
    } catch {
        Write-Log "Error collecting groups: $_" -Level ERROR -Component ADCollector
        return @()
    }
}

#endregion

#region Computers

function Get-ADComputersData {
    param($ADParams)

    $properties = @(
        'SamAccountName','DNSHostName','DistinguishedName','Enabled','OperatingSystem',
        'OperatingSystemVersion','LastLogonDate','TrustedForDelegation','TrustedToAuthForDelegation',
        'ServicePrincipalName','MemberOf','ObjectSID','WhenCreated','Description',
        'msDS-AllowedToDelegateTo','msDS-AllowedToActOnBehalfOfOtherIdentity',
        'PrimaryGroup','isCriticalSystemObject'
    )

    try {
        $computers = Get-ADComputer -Filter * -Properties $properties @ADParams
        return @($computers | ForEach-Object {
            [ordered]@{
                SamAccountName             = $_.SamAccountName
                DNSHostName                = $_.DNSHostName
                DistinguishedName          = $_.DistinguishedName
                Enabled                    = $_.Enabled
                OperatingSystem            = $_.OperatingSystem
                OperatingSystemVersion     = $_.OperatingSystemVersion
                LastLogonDate              = $_.LastLogonDate
                TrustedForDelegation       = $_.TrustedForDelegation
                TrustedToAuthForDelegation = $_.TrustedToAuthForDelegation
                ServicePrincipalNames      = @($_.ServicePrincipalName)
                MemberOf                   = @($_.MemberOf)
                ObjectSID                  = $_.ObjectSID.Value
                WhenCreated                = $_.WhenCreated
                Description                = $_.Description
                AllowedToDelegateTo        = @($_.'msDS-AllowedToDelegateTo')
                IsCriticalSystemObject     = $_.isCriticalSystemObject
            }
        })
    } catch {
        Write-Log "Error collecting computers: $_" -Level ERROR -Component ADCollector
        return @()
    }
}

#endregion

#region Service Accounts

function Get-ServiceAccountsData {
    param($ADParams)

    $properties = @(
        'SamAccountName','UserPrincipalName','DistinguishedName','Enabled',
        'PasswordLastSet','PasswordNeverExpires','ServicePrincipalName',
        'TrustedForDelegation','TrustedToAuthForDelegation','MemberOf',
        'ObjectSID','Description','WhenCreated','AdminCount',
        'msDS-AllowedToDelegateTo','LastLogonDate'
    )

    try {
        # Service accounts: have SPNs, typically in Service Accounts OU or named with svc/sa prefix
        $filter = "ObjectClass -eq 'user' -and (ServicePrincipalName -like '*' -or SamAccountName -like 'svc*' -or SamAccountName -like 'sa-*' -or SamAccountName -like 'srv*')"
        $svcAccts = Get-ADUser -Filter $filter -Properties $properties @ADParams
        return @($svcAccts | ForEach-Object {
            [ordered]@{
                SamAccountName             = $_.SamAccountName
                DistinguishedName          = $_.DistinguishedName
                Enabled                    = $_.Enabled
                PasswordLastSet            = $_.PasswordLastSet
                PasswordNeverExpires       = $_.PasswordNeverExpires
                ServicePrincipalNames      = @($_.ServicePrincipalName)
                TrustedForDelegation       = $_.TrustedForDelegation
                TrustedToAuthForDelegation = $_.TrustedToAuthForDelegation
                MemberOf                   = @($_.MemberOf)
                ObjectSID                  = $_.ObjectSID.Value
                Description                = $_.Description
                WhenCreated                = $_.WhenCreated
                AdminCount                 = $_.AdminCount
                AllowedToDelegateTo        = @($_.'msDS-AllowedToDelegateTo')
                LastLogonDate              = $_.LastLogonDate
            }
        })
    } catch {
        Write-Log "Error collecting service accounts: $_" -Level ERROR -Component ADCollector
        return @()
    }
}

function Get-ManagedServiceAccountsData {
    param($ADParams)
    try {
        $msas = Get-ADServiceAccount -Filter * -Properties * @ADParams
        return @($msas | ForEach-Object {
            [ordered]@{
                SamAccountName        = $_.SamAccountName
                DistinguishedName     = $_.DistinguishedName
                Enabled               = $_.Enabled
                HostComputers         = @($_.HostComputers)
                ServicePrincipalNames = @($_.ServicePrincipalName)
                ObjectSID             = $_.ObjectSID.Value
                WhenCreated           = $_.WhenCreated
                Description           = $_.Description
                IsMSA                 = ($_.ObjectClass -eq 'msDS-ManagedServiceAccount')
                IsGMSA                = ($_.ObjectClass -eq 'msDS-GroupManagedServiceAccount')
            }
        })
    } catch {
        Write-Log "No managed service accounts found or error: $_" -Level WARNING -Component ADCollector
        return @()
    }
}

#endregion

#region OUs and GPOs

function Get-OUData {
    param($ADParams)
    try {
        $ous = Get-ADOrganizationalUnit -Filter * -Properties * @ADParams
        return @($ous | ForEach-Object {
            [ordered]@{
                Name              = $_.Name
                DistinguishedName = $_.DistinguishedName
                Description       = $_.Description
                ManagedBy         = $_.ManagedBy
                LinkedGroupPolicies = @($_.LinkedGroupPolicyObjects)
                WhenCreated       = $_.WhenCreated
                Protected         = $_.ProtectedFromAccidentalDeletion
            }
        })
    } catch {
        Write-Log "Error collecting OUs: $_" -Level ERROR -Component ADCollector
        return @()
    }
}

function Get-GPOData {
    param($ADParams)
    try {
        Import-Module GroupPolicy -ErrorAction Stop
        $gpos = Get-GPO -All @ADParams -ErrorAction Stop
        return @($gpos | ForEach-Object {
            [ordered]@{
                DisplayName         = $_.DisplayName
                Id                  = $_.Id.ToString()
                GpoStatus           = $_.GpoStatus.ToString()
                Description         = $_.Description
                CreationTime        = $_.CreationTime
                ModificationTime    = $_.ModificationTime
                UserVersion         = $_.User.DSVersion
                ComputerVersion     = $_.Computer.DSVersion
                WmiFilter           = $_.WmiFilter
            }
        })
    } catch {
        Write-Log "GroupPolicy module unavailable or error: $_" -Level WARNING -Component ADCollector
        return @()
    }
}

#endregion

#region Domain Controllers and Trusts

function Get-DomainControllerData {
    param($ADParams)
    try {
        $dcs = Get-ADDomainController -Filter * @ADParams
        return @($dcs | ForEach-Object {
            [ordered]@{
                Name               = $_.Name
                HostName           = $_.HostName
                IPv4Address        = $_.IPv4Address
                Site               = $_.Site
                IsGlobalCatalog    = $_.IsGlobalCatalog
                IsReadOnly         = $_.IsReadOnly
                OperatingSystem    = $_.OperatingSystem
                Enabled            = $_.Enabled
                OperationMasterRoles = @($_.OperationMasterRoles | ForEach-Object { $_.ToString() })
            }
        })
    } catch {
        Write-Log "Error collecting domain controllers: $_" -Level ERROR -Component ADCollector
        return @()
    }
}

function Get-TrustData {
    param($ADParams)
    try {
        $trusts = Get-ADTrust -Filter * -Properties * @ADParams
        return @($trusts | ForEach-Object {
            [ordered]@{
                Name             = $_.Name
                Source           = $_.Source
                Target           = $_.Target
                TrustType        = $_.TrustType.ToString()
                TrustDirection   = $_.TrustDirection.ToString()
                TrustAttributes  = $_.TrustAttributes
                SID              = $_.securityIdentifier
                IsTransitive     = ($_.TrustAttributes -band 0x8) -eq 0
                SIDFilteringEnabled = ($_.TrustAttributes -band 0x4) -ne 0
            }
        })
    } catch {
        Write-Log "Error collecting trusts: $_" -Level ERROR -Component ADCollector
        return @()
    }
}

#endregion

#region Privileged Groups

function Get-PrivilegedGroupsData {
    param($ADParams, $Config)

    $privilegedGroups = @()
    foreach ($groupName in $Config.Analysis.PrivilegedGroups) {
        try {
            $group = Get-ADGroup -Filter "SamAccountName -eq '$groupName'" -Properties Members,Description,ManagedBy @ADParams
            if (-not $group) { continue }

            $nestedMembers = @()
            try { $nestedMembers = @(Get-ADGroupMember -Identity $group.DistinguishedName -Recursive @ADParams | ForEach-Object { $_.SamAccountName }) }
            catch { }

            $directMembers = @()
            try { $directMembers = @(Get-ADGroupMember -Identity $group.DistinguishedName @ADParams | ForEach-Object { $_.SamAccountName }) }
            catch { }

            $privilegedGroups += [ordered]@{
                Name              = $groupName
                DistinguishedName = $group.DistinguishedName
                Description       = $group.Description
                ManagedBy         = $group.ManagedBy
                DirectMemberCount = $directMembers.Count
                DirectMembers     = $directMembers
                NestedMemberCount = $nestedMembers.Count
                NestedMembers     = $nestedMembers
                IsTier0           = $Config.Analysis.Tier0Groups -contains $groupName
            }
        } catch {
            Write-Log "Could not enumerate group '$groupName': $_" -Level DEBUG -Component ADCollector
        }
    }
    return $privilegedGroups
}

#endregion

#region ACL Analysis

function Get-ACLFindings {
    param($ADParams, $Domain)

    $findings = @()
    $dangerousRights = @('GenericAll','GenericWrite','WriteDacl','WriteOwner','AllExtendedRights')
    $interestingRights = @('AddMember','Self','WriteProperty')

    # Rights that allow password reset
    $extendedRightGuids = @{
        'User-Force-Change-Password' = 'ab721a53-1e2f-11d0-9819-00aa0040529b'
        'DS-Replication-Get-Changes' = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
        'DS-Replication-Get-Changes-All' = '1131f6ab-9c07-11d1-f79f-00c04fc2dcd2'
        'DS-Replication-Get-Changes-In-Filtered-Set' = '89e95b76-444d-4c62-991a-0facbeda640c'
    }

    $domainDN = $Domain.DistinguishedName
    $highValueOUs = @(
        $domainDN,
        "CN=Admins,$domainDN",
        "CN=Users,$domainDN",
        "OU=Domain Controllers,$domainDN"
    )

    # Get all AD objects with ACLs (sampled - full scan is expensive)
    $searchBases = @($domainDN)
    try {
        $privilegedOUs = Get-ADOrganizationalUnit -Filter * -SearchBase "OU=Domain Controllers,$domainDN" @ADParams -SearchScope Base 2>$null
        if ($privilegedOUs) { $searchBases += $privilegedOUs.DistinguishedName }
    } catch {}

    $schemaIDGUIDMap = @{}
    try {
        $schema = [System.DirectoryServices.ActiveDirectory.ActiveDirectorySchema]::GetCurrentSchema()
        Get-ADObject -SearchBase "CN=Schema,$((Get-ADRootDSE).schemaNamingContext)" -Filter * -Properties schemaIDGUID,ldapDisplayName @ADParams | ForEach-Object {
            if ($_.schemaIDGUID) {
                $schemaIDGUIDMap[[System.Guid]$_.schemaIDGUID] = $_.ldapDisplayName
            }
        }
    } catch {}

    # Check domain root ACL for DCSync rights
    try {
        $domainPath = "AD:\$domainDN"
        $acl = Get-Acl -Path $domainPath
        foreach ($ace in $acl.Access) {
            $identity = $ace.IdentityReference.ToString()
            $rights   = $ace.ActiveDirectoryRights.ToString()

            # Skip well-known safe SIDs
            if ($identity -match 'NT AUTHORITY|SYSTEM|Domain Admins|Enterprise Admins|Administrators|CREATOR OWNER|SELF') { continue }

            $activeRights = $ace.ActiveDirectoryRights
            $objectType   = $ace.ObjectType

            $isDCSync  = ($objectType -eq [Guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2') -or
                         ($objectType -eq [Guid]'1131f6ab-9c07-11d1-f79f-00c04fc2dcd2') -or
                         ($objectType -eq [Guid]'89e95b76-444d-4c62-991a-0facbeda640c')

            $isGenericAll   = $activeRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
            $isGenericWrite = $activeRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite
            $isWriteDACL    = $activeRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl
            $isWriteOwner   = $activeRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner

            if ($isDCSync -or $isGenericAll -or $isGenericWrite -or $isWriteDACL -or $isWriteOwner) {
                $findingType = if ($isDCSync) { 'DCSyncRight' }
                               elseif ($isGenericAll) { 'GenericAll' }
                               elseif ($isGenericWrite) { 'GenericWrite' }
                               elseif ($isWriteDACL) { 'WriteDACL' }
                               else { 'WriteOwner' }

                $findings += [ordered]@{
                    FindingType       = $findingType
                    SourceIdentity    = $identity
                    TargetObject      = $domainDN
                    TargetObjectType  = 'Domain'
                    Rights            = $rights
                    AceType           = $ace.AccessControlType.ToString()
                    Inherited         = $ace.IsInherited
                    ObjectType        = $ace.ObjectType.ToString()
                    InheritedObjectType = $ace.InheritedObjectType.ToString()
                }
            }
        }
    } catch {
        Write-Log "Error reading domain root ACL: $_" -Level WARNING -Component ACLAnalysis
    }

    # Scan privileged group ACLs
    $privGroupNames = @('Domain Admins','Enterprise Admins','Schema Admins','Administrators','Account Operators','Backup Operators','Group Policy Creator Owners','DNSAdmins')
    foreach ($gName in $privGroupNames) {
        try {
            $grp = Get-ADGroup $gName @ADParams -ErrorAction SilentlyContinue
            if (-not $grp) { continue }
            $path = "AD:\$($grp.DistinguishedName)"
            $acl  = Get-Acl -Path $path
            foreach ($ace in $acl.Access) {
                $identity = $ace.IdentityReference.ToString()
                if ($identity -match 'NT AUTHORITY|SYSTEM|Domain Admins|Enterprise Admins|Administrators|CREATOR OWNER') { continue }
                $activeRights = $ace.ActiveDirectoryRights
                $isRisky = ($activeRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll) -or
                           ($activeRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite) -or
                           ($activeRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl) -or
                           ($activeRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner) -or
                           ($activeRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) -or
                           ($activeRights -band [System.DirectoryServices.ActiveDirectoryRights]::Self)

                if ($isRisky) {
                    $rights = $ace.ActiveDirectoryRights.ToString()
                    $findingType = if ($activeRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll) { 'GenericAll' }
                                   elseif ($activeRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite) { 'GenericWrite' }
                                   elseif ($activeRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl) { 'WriteDACL' }
                                   elseif ($activeRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner) { 'WriteOwner' }
                                   else { 'WriteProperty' }

                    $findings += [ordered]@{
                        FindingType      = $findingType
                        SourceIdentity   = $identity
                        TargetObject     = $grp.DistinguishedName
                        TargetObjectType = 'PrivilegedGroup'
                        TargetName       = $gName
                        Rights           = $rights
                        AceType          = $ace.AccessControlType.ToString()
                        Inherited        = $ace.IsInherited
                    }
                }
            }
        } catch {
            Write-Log "Error reading ACL for group '$gName': $_" -Level DEBUG -Component ACLAnalysis
        }
    }

    return $findings
}

function Get-DelegationFindings {
    param($ADParams)

    $findings = @()

    # Unconstrained delegation (computers/users with TrustedForDelegation, excluding DCs)
    try {
        $unconstrainedUsers = Get-ADUser -Filter "TrustedForDelegation -eq $true" -Properties TrustedForDelegation,SamAccountName,DistinguishedName,Enabled @ADParams
        foreach ($u in $unconstrainedUsers) {
            $findings += [ordered]@{
                Type              = 'UnconstrainedDelegation'
                ObjectName        = $u.SamAccountName
                ObjectType        = 'User'
                DistinguishedName = $u.DistinguishedName
                Enabled           = $u.Enabled
                Risk              = 'Critical'
                Description       = 'Account configured with unconstrained Kerberos delegation - allows credential harvesting'
            }
        }
    } catch { Write-Log "Error checking unconstrained delegation (users): $_" -Level WARNING -Component ADCollector }

    try {
        $unconstrainedComputers = Get-ADComputer -Filter "TrustedForDelegation -eq $true" -Properties TrustedForDelegation,SamAccountName,DistinguishedName,Enabled,isCriticalSystemObject @ADParams
        foreach ($c in $unconstrainedComputers) {
            if ($c.isCriticalSystemObject) { continue } # Skip DCs
            $findings += [ordered]@{
                Type              = 'UnconstrainedDelegation'
                ObjectName        = $c.SamAccountName
                ObjectType        = 'Computer'
                DistinguishedName = $c.DistinguishedName
                Enabled           = $c.Enabled
                Risk              = 'High'
                Description       = 'Computer configured with unconstrained Kerberos delegation - can be abused for credential theft'
            }
        }
    } catch { Write-Log "Error checking unconstrained delegation (computers): $_" -Level WARNING -Component ADCollector }

    # Constrained delegation
    try {
        $constrainedUsers = Get-ADUser -Filter "msDS-AllowedToDelegateTo -like '*'" -Properties 'msDS-AllowedToDelegateTo','TrustedToAuthForDelegation','SamAccountName','DistinguishedName' @ADParams
        foreach ($u in $constrainedUsers) {
            $delegationType = if ($u.TrustedToAuthForDelegation) { 'ConstrainedDelegationAnyProtocol' } else { 'ConstrainedDelegation' }
            $findings += [ordered]@{
                Type              = $delegationType
                ObjectName        = $u.SamAccountName
                ObjectType        = 'User'
                DistinguishedName = $u.DistinguishedName
                DelegatesTo       = @($u.'msDS-AllowedToDelegateTo')
                Risk              = if ($u.TrustedToAuthForDelegation) { 'High' } else { 'Medium' }
                Description       = "Account has constrained delegation configured. Protocol transition: $($u.TrustedToAuthForDelegation)"
            }
        }
    } catch { Write-Log "Error checking constrained delegation: $_" -Level WARNING -Component ADCollector }

    # Resource-Based Constrained Delegation (RBCD)
    try {
        $rbcdObjects = Get-ADComputer -Filter "msDS-AllowedToActOnBehalfOfOtherIdentity -like '*'" -Properties 'msDS-AllowedToActOnBehalfOfOtherIdentity','SamAccountName','DistinguishedName' @ADParams
        foreach ($obj in $rbcdObjects) {
            $findings += [ordered]@{
                Type              = 'ResourceBasedConstrainedDelegation'
                ObjectName        = $obj.SamAccountName
                ObjectType        = 'Computer'
                DistinguishedName = $obj.DistinguishedName
                Risk              = 'High'
                Description       = 'Computer has RBCD configured - check which accounts can impersonate any user to this service'
            }
        }
    } catch { Write-Log "Error checking RBCD: $_" -Level WARNING -Component ADCollector }

    return $findings
}

#endregion

#region Kerberoasting / AS-REP

function Get-KerberoastableAccounts {
    param($ADParams)
    try {
        $kerbUsers = Get-ADUser -Filter "ServicePrincipalName -like '*' -and Enabled -eq $true" `
            -Properties SamAccountName,ServicePrincipalName,PasswordLastSet,AdminCount,MemberOf,DistinguishedName @ADParams
        return @($kerbUsers | ForEach-Object {
            [ordered]@{
                SamAccountName    = $_.SamAccountName
                DistinguishedName = $_.DistinguishedName
                SPNs              = @($_.ServicePrincipalName)
                PasswordLastSet   = $_.PasswordLastSet
                AdminCount        = $_.AdminCount
                MemberOf          = @($_.MemberOf)
                IsHighPrivilege   = ($_.AdminCount -eq 1)
            }
        })
    } catch {
        Write-Log "Error finding Kerberoastable accounts: $_" -Level WARNING -Component ADCollector
        return @()
    }
}

function Get-ASREPRoastableAccounts {
    param($ADParams)
    try {
        $asrepUsers = Get-ADUser -Filter "DoesNotRequirePreAuth -eq $true -and Enabled -eq $true" `
            -Properties SamAccountName,DistinguishedName,PasswordLastSet,AdminCount,MemberOf @ADParams
        return @($asrepUsers | ForEach-Object {
            [ordered]@{
                SamAccountName    = $_.SamAccountName
                DistinguishedName = $_.DistinguishedName
                PasswordLastSet   = $_.PasswordLastSet
                AdminCount        = $_.AdminCount
                MemberOf          = @($_.MemberOf)
                IsHighPrivilege   = ($_.AdminCount -eq 1)
            }
        })
    } catch {
        Write-Log "Error finding AS-REP Roastable accounts: $_" -Level WARNING -Component ADCollector
        return @()
    }
}

#endregion

#region SID History, AdminCount, Orphaned SIDs

function Get-SIDHistoryAccounts {
    param($ADParams)
    try {
        $sidHistUsers = Get-ADUser -Filter "SIDHistory -like '*'" -Properties SamAccountName,SIDHistory,DistinguishedName,Enabled,AdminCount @ADParams
        return @($sidHistUsers | ForEach-Object {
            [ordered]@{
                SamAccountName    = $_.SamAccountName
                DistinguishedName = $_.DistinguishedName
                Enabled           = $_.Enabled
                AdminCount        = $_.AdminCount
                SIDHistory        = @($_.SIDHistory | ForEach-Object { $_.Value })
            }
        })
    } catch {
        Write-Log "Error finding SID history accounts: $_" -Level WARNING -Component ADCollector
        return @()
    }
}

function Get-AdminCountAccounts {
    param($ADParams)
    try {
        $adminCountUsers = Get-ADUser -Filter "AdminCount -eq 1" -Properties SamAccountName,DistinguishedName,Enabled,PasswordLastSet,LastLogonDate,MemberOf @ADParams
        return @($adminCountUsers | ForEach-Object {
            [ordered]@{
                SamAccountName    = $_.SamAccountName
                DistinguishedName = $_.DistinguishedName
                Enabled           = $_.Enabled
                PasswordLastSet   = $_.PasswordLastSet
                LastLogonDate     = $_.LastLogonDate
                MemberOf          = @($_.MemberOf)
            }
        })
    } catch {
        Write-Log "Error finding AdminCount accounts: $_" -Level WARNING -Component ADCollector
        return @()
    }
}

function Get-OrphanedSIDs {
    param($ADParams, $Domain)
    $orphaned = @()
    $domainSID = $Domain.DomainSID.Value
    try {
        $domainPath = "AD:\$($Domain.DistinguishedName)"
        $acl = Get-Acl -Path $domainPath
        foreach ($ace in $acl.Access) {
            $id = $ace.IdentityReference.ToString()
            if ($id -match '^S-1-' -and $id -notmatch 'S-1-5-32|S-1-5-18|S-1-1-0|S-1-5-11') {
                $orphaned += [ordered]@{
                    SID        = $id
                    Rights     = $ace.ActiveDirectoryRights.ToString()
                    TargetPath = $Domain.DistinguishedName
                }
            }
        }
    } catch {
        Write-Log "Error finding orphaned SIDs: $_" -Level WARNING -Component ADCollector
    }
    return $orphaned
}

#endregion

#region Password Findings

function Get-PasswordFindings {
    param($ADParams)
    $findings = @()
    try {
        $pwdNeverExpires = Get-ADUser -Filter "PasswordNeverExpires -eq $true -and Enabled -eq $true" `
            -Properties SamAccountName,DistinguishedName,PasswordLastSet,AdminCount @ADParams
        foreach ($u in $pwdNeverExpires) {
            $findings += [ordered]@{
                FindingType       = 'PasswordNeverExpires'
                SamAccountName    = $u.SamAccountName
                DistinguishedName = $u.DistinguishedName
                PasswordLastSet   = $u.PasswordLastSet
                AdminCount        = $u.AdminCount
                IsPrivileged      = ($u.AdminCount -eq 1)
            }
        }
    } catch { Write-Log "Error finding password-never-expires: $_" -Level WARNING -Component ADCollector }

    try {
        $pwdNotRequired = Get-ADUser -Filter "PasswordNotRequired -eq $true -and Enabled -eq $true" `
            -Properties SamAccountName,DistinguishedName,AdminCount @ADParams
        foreach ($u in $pwdNotRequired) {
            $findings += [ordered]@{
                FindingType       = 'PasswordNotRequired'
                SamAccountName    = $u.SamAccountName
                DistinguishedName = $u.DistinguishedName
                PasswordLastSet   = $null
                AdminCount        = $u.AdminCount
                IsPrivileged      = ($u.AdminCount -eq 1)
            }
        }
    } catch { Write-Log "Error finding password-not-required: $_" -Level WARNING -Component ADCollector }

    try {
        $reversiblePwd = Get-ADUser -Filter "AllowReversiblePasswordEncryption -eq $true -and Enabled -eq $true" `
            -Properties SamAccountName,DistinguishedName,AdminCount @ADParams
        foreach ($u in $reversiblePwd) {
            $findings += [ordered]@{
                FindingType       = 'ReversiblePasswordEncryption'
                SamAccountName    = $u.SamAccountName
                DistinguishedName = $u.DistinguishedName
                AdminCount        = $u.AdminCount
                IsPrivileged      = ($u.AdminCount -eq 1)
            }
        }
    } catch { Write-Log "Error finding reversible password encryption: $_" -Level WARNING -Component ADCollector }

    return $findings
}

function Get-ProtectedUsersData {
    param($ADParams)
    try {
        $pu = Get-ADGroupMember -Identity 'Protected Users' -Recursive @ADParams -ErrorAction SilentlyContinue
        return @($pu | ForEach-Object { $_.SamAccountName })
    } catch {
        return @()
    }
}

function Get-FineGrainedPasswordPolicies {
    param($ADParams)
    try {
        $fgpps = Get-ADFineGrainedPasswordPolicy -Filter * -Properties * @ADParams
        return @($fgpps | ForEach-Object {
            [ordered]@{
                Name                     = $_.Name
                Precedence               = $_.Precedence
                MinPasswordLength        = $_.MinPasswordLength
                PasswordHistoryCount     = $_.PasswordHistoryCount
                MaxPasswordAge           = $_.MaxPasswordAge.TotalDays
                MinPasswordAge           = $_.MinPasswordAge.TotalDays
                LockoutThreshold         = $_.LockoutThreshold
                LockoutDuration          = $_.LockoutDuration.TotalMinutes
                ReversibleEncryption     = $_.ReversibleEncryptionEnabled
                ComplexityEnabled        = $_.ComplexityEnabled
                AppliesToDN              = @($_.AppliesTo)
            }
        })
    } catch {
        Write-Log "No Fine-Grained Password Policies or error: $_" -Level DEBUG -Component ADCollector
        return @()
    }
}

#endregion

#region Stale / Dormant Accounts

function Get-StaleAccounts {
    param($ADParams, [int]$StaleDays = 90)
    $cutoff = (Get-Date).AddDays(-$StaleDays)
    try {
        $stale = Get-ADUser -Filter "LastLogonDate -lt '$cutoff' -and Enabled -eq $true" `
            -Properties SamAccountName,DistinguishedName,LastLogonDate,PasswordLastSet,AdminCount @ADParams
        return @($stale | ForEach-Object {
            [ordered]@{
                SamAccountName    = $_.SamAccountName
                DistinguishedName = $_.DistinguishedName
                LastLogonDate     = $_.LastLogonDate
                PasswordLastSet   = $_.PasswordLastSet
                AdminCount        = $_.AdminCount
                DaysSinceLogin    = if ($_.LastLogonDate) { [int]((Get-Date) - $_.LastLogonDate).TotalDays } else { 9999 }
                IsPrivileged      = ($_.AdminCount -eq 1)
            }
        })
    } catch {
        Write-Log "Error finding stale accounts: $_" -Level WARNING -Component ADCollector
        return @()
    }
}

function Get-DormantPrivilegedAccounts {
    param($ADParams, [int]$DormantDays = 30, $Config)
    $cutoff = (Get-Date).AddDays(-$DormantDays)
    $dormant = @()
    foreach ($groupName in $Config.Analysis.PrivilegedGroups) {
        try {
            $members = Get-ADGroupMember -Identity $groupName -Recursive @ADParams -ErrorAction SilentlyContinue
            foreach ($m in $members) {
                if ($m.objectClass -ne 'user') { continue }
                $u = Get-ADUser -Identity $m.SamAccountName -Properties LastLogonDate,Enabled,PasswordLastSet @ADParams -ErrorAction SilentlyContinue
                if (-not $u -or -not $u.Enabled) { continue }
                if ($u.LastLogonDate -and $u.LastLogonDate -lt $cutoff) {
                    $dormant += [ordered]@{
                        SamAccountName    = $u.SamAccountName
                        DistinguishedName = $u.DistinguishedName
                        PrivilegedGroup   = $groupName
                        LastLogonDate     = $u.LastLogonDate
                        DaysDormant       = [int]((Get-Date) - $u.LastLogonDate).TotalDays
                        PasswordLastSet   = $u.PasswordLastSet
                    }
                }
            }
        } catch { }
    }
    return $dormant
}

#endregion

#region Shadow Admins and DCSync

function Get-ShadowAdmins {
    param($ADParams, $Domain)

    $shadowAdmins = @()
    $domainDN = $Domain.DistinguishedName

    # Get direct AdminSDHolder members vs actual group members to find orphaned AdminCount=1
    try {
        $adminSDHolderPath = "CN=AdminSDHolder,CN=System,$domainDN"
        $adminSDHolderACL  = Get-Acl -Path "AD:\$adminSDHolderPath" -ErrorAction SilentlyContinue
    } catch {}

    try {
        $allAdminCount = Get-ADUser -Filter "AdminCount -eq 1 -and Enabled -eq $true" `
            -Properties SamAccountName,DistinguishedName,MemberOf,LastLogonDate @ADParams

        $legitPrivUsers = @()
        foreach ($groupName in @('Domain Admins','Enterprise Admins','Schema Admins','Administrators','Account Operators','Backup Operators','Print Operators','Server Operators')) {
            try {
                $members = Get-ADGroupMember -Identity $groupName -Recursive @ADParams -ErrorAction SilentlyContinue
                $legitPrivUsers += @($members | Where-Object { $_.objectClass -eq 'user' } | ForEach-Object { $_.SamAccountName })
            } catch {}
        }
        $legitPrivUsers = $legitPrivUsers | Sort-Object -Unique

        foreach ($u in $allAdminCount) {
            if ($legitPrivUsers -notcontains $u.SamAccountName) {
                $shadowAdmins += [ordered]@{
                    SamAccountName    = $u.SamAccountName
                    DistinguishedName = $u.DistinguishedName
                    LastLogonDate     = $u.LastLogonDate
                    MemberOf          = @($u.MemberOf)
                    Reason            = 'AdminCount=1 but not in any standard privileged group'
                    Risk              = 'High'
                }
            }
        }
    } catch {
        Write-Log "Error finding shadow admins: $_" -Level WARNING -Component ADCollector
    }
    return $shadowAdmins
}

function Get-DCSyncAccounts {
    param($ADParams, $Domain)

    $dcsyncAccounts = @()
    $dcsyncRightGuids = @(
        [Guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', # DS-Replication-Get-Changes
        [Guid]'1131f6ab-9c07-11d1-f79f-00c04fc2dcd2', # DS-Replication-Get-Changes-All
        [Guid]'89e95b76-444d-4c62-991a-0facbeda640c'  # DS-Replication-Get-Changes-In-Filtered-Set
    )

    try {
        $domainPath = "AD:\$($Domain.DistinguishedName)"
        $acl = Get-Acl -Path $domainPath
        $rightHolders = @{}
        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            $identity = $ace.IdentityReference.ToString()
            if ($identity -match 'NT AUTHORITY|Domain Controllers|Enterprise Domain Controllers|Administrators|Domain Admins|Enterprise Admins') { continue }
            if ($dcsyncRightGuids -contains $ace.ObjectType) {
                if (-not $rightHolders.ContainsKey($identity)) {
                    $rightHolders[$identity] = @()
                }
                $rightName = switch ($ace.ObjectType) {
                    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' { 'DS-Replication-Get-Changes' }
                    '1131f6ab-9c07-11d1-f79f-00c04fc2dcd2' { 'DS-Replication-Get-Changes-All' }
                    '89e95b76-444d-4c62-991a-0facbeda640c' { 'DS-Replication-Get-Changes-In-Filtered-Set' }
                    default { $ace.ObjectType.ToString() }
                }
                $rightHolders[$identity] += $rightName
            }
        }

        foreach ($identity in $rightHolders.Keys) {
            $rights = $rightHolders[$identity]
            # DCSync requires both Get-Changes AND Get-Changes-All
            $hasFullDCSync = ($rights -contains 'DS-Replication-Get-Changes') -and ($rights -contains 'DS-Replication-Get-Changes-All')
            $dcsyncAccounts += [ordered]@{
                Identity        = $identity
                Rights          = $rights
                HasFullDCSync   = $hasFullDCSync
                Risk            = if ($hasFullDCSync) { 'Critical' } else { 'High' }
                Description     = if ($hasFullDCSync) { 'Full DCSync capability - can replicate all domain secrets' }
                                  else { 'Partial replication rights - potential for targeted secret extraction' }
            }
        }
    } catch {
        Write-Log "Error finding DCSync accounts: $_" -Level WARNING -Component ADCollector
    }
    return $dcsyncAccounts
}

#endregion

#region Tier Classification

function Get-Tier0Objects {
    param($ADParams, $Config)
    $tier0 = @()
    foreach ($groupName in $Config.Analysis.Tier0Groups) {
        try {
            $group = Get-ADGroup $groupName @ADParams -ErrorAction SilentlyContinue
            if (-not $group) { continue }
            $members = Get-ADGroupMember -Identity $groupName -Recursive @ADParams -ErrorAction SilentlyContinue
            foreach ($m in $members) {
                $tier0 += [ordered]@{
                    Name              = $m.SamAccountName
                    ObjectType        = $m.objectClass
                    DistinguishedName = $m.DistinguishedName
                    Tier0Group        = $groupName
                }
            }
        } catch {}
    }
    return $tier0 | Sort-Object Name -Unique
}

function Get-Tier1Objects {
    param($ADParams, $Config)
    $tier1 = @()
    foreach ($groupName in $Config.Analysis.Tier1Groups) {
        try {
            $members = Get-ADGroupMember -Identity $groupName -Recursive @ADParams -ErrorAction SilentlyContinue
            foreach ($m in $members) {
                $tier1 += [ordered]@{
                    Name              = $m.SamAccountName
                    ObjectType        = $m.objectClass
                    DistinguishedName = $m.DistinguishedName
                    Tier1Group        = $groupName
                }
            }
        } catch {}
    }
    return $tier1 | Sort-Object Name -Unique
}

#endregion

#region Circular Group Detection

function Find-CircularGroupMemberships {
    param($Groups)

    $circular = @()
    $groupMap  = @{}
    foreach ($g in $Groups) {
        $groupMap[$g.DistinguishedName] = $g
    }

    foreach ($g in $Groups) {
        $visited = @{}
        $stack   = [System.Collections.Generic.Stack[string]]::new()
        $stack.Push($g.DistinguishedName)

        while ($stack.Count -gt 0) {
            $current = $stack.Pop()
            if ($visited.ContainsKey($current)) {
                if ($current -eq $g.DistinguishedName) {
                    $circular += [ordered]@{
                        Group     = $g.SamAccountName
                        DN        = $g.DistinguishedName
                        Reason    = 'Circular membership detected'
                    }
                }
                continue
            }
            $visited[$current] = $true
            if ($groupMap.ContainsKey($current)) {
                foreach ($memberDN in $groupMap[$current].Members) {
                    if ($groupMap.ContainsKey($memberDN)) {
                        $stack.Push($memberDN)
                    }
                }
            }
        }
    }
    return $circular
}

#endregion

#region DC Resolution and Credential Helpers

function Resolve-TargetDomainController {
    <#
    .SYNOPSIS
        Selects the best Domain Controller to use for all AD queries.
        Priority: config explicit list → PDC Emulator auto-discovery → DNS default.
    #>
    [CmdletBinding()]
    param(
        [hashtable]$Config,
        [System.Management.Automation.PSCredential]$Credential
    )

    # 1. Config has explicit DC list — try first reachable one
    if ($Config.General.DomainControllers -and $Config.General.DomainControllers.Count -gt 0) {
        foreach ($dc in $Config.General.DomainControllers) {
            if (Test-Connection -ComputerName $dc -Count 1 -Quiet -ErrorAction SilentlyContinue) {
                Write-Log "Using config-specified DC: $dc" -Level INFO -Component ADCollector
                return $dc
            } else {
                Write-Log "Config DC unreachable: $dc" -Level WARNING -Component ADCollector
            }
        }
        Write-Log "All config-specified DCs unreachable. Falling back to PDC Emulator." -Level WARNING -Component ADCollector
    }

    # 2. Auto-discover PDC Emulator (authoritative, always current)
    try {
        $tempParams = @{ ErrorAction = 'Stop' }
        if ($Credential) { $tempParams.Credential = $Credential }
        if ($Config.General.TargetDomain) { $tempParams.Identity = $Config.General.TargetDomain }

        $domain = Get-ADDomain @tempParams
        $pdc    = $domain.PDCEmulator
        if ($pdc -and (Test-Connection -ComputerName $pdc -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
            Write-Log "Auto-selected PDC Emulator: $pdc" -Level INFO -Component ADCollector
            return $pdc
        }
    } catch {
        Write-Log "PDC Emulator discovery failed: $_" -Level WARNING -Component ADCollector
    }

    # 3. Enumerate DCs and pick the first in the local site
    try {
        $tempParams = @{ ErrorAction = 'Stop' }
        if ($Credential) { $tempParams.Credential = $Credential }
        $dcs = Get-ADDomainController -Filter * @tempParams | Sort-Object { $_.IsGlobalCatalog } -Descending
        foreach ($dc in $dcs) {
            if (-not $dc.IsReadOnly -and (Test-Connection -ComputerName $dc.HostName -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
                Write-Log "Selected writable DC from discovery: $($dc.HostName)" -Level INFO -Component ADCollector
                return $dc.HostName
            }
        }
    } catch {
        Write-Log "DC enumeration failed: $_" -Level WARNING -Component ADCollector
    }

    # 4. No explicit DC — let AD module use DNS SRV records
    Write-Log "No specific DC selected. AD module will use DNS SRV lookup." -Level INFO -Component ADCollector
    return $null
}

function Get-CredentialFromVault {
    <#
    .SYNOPSIS
        Retrieves a stored credential from Windows Credential Manager (DPAPI-encrypted).
        Works in non-interactive / scheduled task context without prompting.
    #>
    [CmdletBinding()]
    param([string]$Target)

    # Windows Credential Manager via P/Invoke
    try {
        $signature = @"
[DllImport("advapi32.dll", EntryPoint="CredReadW", CharSet=CharSet.Unicode, SetLastError=true)]
public static extern bool CredRead(string target, int type, int flags, out IntPtr credential);

[DllImport("advapi32.dll", EntryPoint="CredFree")]
public static extern void CredFree(IntPtr credential);

[StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
public struct CREDENTIAL {
    public int Flags;
    public int Type;
    public string TargetName;
    public string Comment;
    public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
    public int CredentialBlobSize;
    public IntPtr CredentialBlob;
    public int Persist;
    public int AttributeCount;
    public IntPtr Attributes;
    public string TargetAlias;
    public string UserName;
}
"@
        if (-not ([System.Management.Automation.PSTypeName]'CredManager').Type) {
            Add-Type -MemberDefinition $signature -Name 'CredManager' -Namespace 'WinCred' -ErrorAction Stop
        }

        [IntPtr]$credPtr = [IntPtr]::Zero
        $ok = [WinCred.CredManager]::CredRead($Target, 1, 0, [ref]$credPtr)

        if ($ok -and $credPtr -ne [IntPtr]::Zero) {
            $cred     = [System.Runtime.InteropServices.Marshal]::PtrToStructure($credPtr, [type][WinCred.CredManager+CREDENTIAL]) 2>$null
            $userName = $cred.UserName
            if ($cred.CredentialBlobSize -gt 0) {
                $pwBytes = [byte[]]::new($cred.CredentialBlobSize)
                [System.Runtime.InteropServices.Marshal]::Copy($cred.CredentialBlob, $pwBytes, 0, $cred.CredentialBlobSize)
                $pwPlain = [System.Text.Encoding]::Unicode.GetString($pwBytes)
                $secPwd  = ConvertTo-SecureString $pwPlain -AsPlainText -Force
                [WinCred.CredManager]::CredFree($credPtr)
                Write-Log "Credential loaded from Windows Credential Manager: $Target ($userName)" -Level SUCCESS -Component CredVault
                return [System.Management.Automation.PSCredential]::new($userName, $secPwd)
            }
            [WinCred.CredManager]::CredFree($credPtr)
        }
    } catch {
        Write-Log "Credential Manager P/Invoke failed: $_" -Level DEBUG -Component CredVault
    }

    # Fallback: cmdkey-based check (no extraction possible — just signals presence)
    $cmdkeyResult = cmdkey /list:$Target 2>$null
    if ($cmdkeyResult -match "Target:.*$Target") {
        Write-Log "Credential exists in cmdkey store for '$Target' but cannot be extracted via P/Invoke. Verify Add-Type succeeded." -Level WARNING -Component CredVault
    } else {
        Write-Log "No credential found in Credential Manager for target: $Target" -Level WARNING -Component CredVault
    }
    return $null
}

function Test-IsGroupManagedServiceAccount {
    <#
    .SYNOPSIS
        Detects if the current process is running as a gMSA (Group Managed Service Account).
        gMSAs never need an explicit credential — the system handles the password automatically.
    #>
    [CmdletBinding()]
    param()
    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $name     = $identity.Name
        # gMSA accounts always end with a $ in the SAM name
        if ($name -match '\$$') {
            $samName = $name.Split('\')[-1].TrimEnd('$')
            $acct    = Get-ADServiceAccount -Filter "SamAccountName -eq '$samName'" -ErrorAction SilentlyContinue
            if ($acct) {
                Write-Log "Running as Group Managed Service Account: $name" -Level SUCCESS -Component CredVault
                return $true
            }
        }
    } catch { }
    return $false
}

#endregion

Export-ModuleMember -Function Invoke-ADDataCollection, Get-DomainInfo, Get-ForestInfo,
    Resolve-TargetDomainController, Get-CredentialFromVault, Test-IsGroupManagedServiceAccount,
    Get-ADUsersData, Get-ADGroupsData, Get-ADComputersData, Get-ServiceAccountsData,
    Get-ManagedServiceAccountsData, Get-OUData, Get-GPOData, Get-DomainControllerData,
    Get-TrustData, Get-PrivilegedGroupsData, Get-ACLFindings, Get-DelegationFindings,
    Get-KerberoastableAccounts, Get-ASREPRoastableAccounts, Get-SIDHistoryAccounts,
    Get-AdminCountAccounts, Get-OrphanedSIDs, Get-PasswordFindings, Get-ProtectedUsersData,
    Get-FineGrainedPasswordPolicies, Get-StaleAccounts, Get-DormantPrivilegedAccounts,
    Get-ShadowAdmins, Get-DCSyncAccounts, Get-Tier0Objects, Get-Tier1Objects,
    Find-CircularGroupMemberships
