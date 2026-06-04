#Requires -Version 5.1
<#
.SYNOPSIS
    BloodHound Community Edition and Enterprise integration module.
    Enriches native PowerShell findings with graph-based attack paths from BloodHound.
#>

#region Connection

function Connect-BloodHoundCE {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ServerUrl,

        [string]$Username,
        [securestring]$Password,
        [string]$ApiKey
    )

    $script:BHBaseUrl  = $ServerUrl.TrimEnd('/')
    $script:BHEdition  = 'Community'
    $script:BHHeaders  = @{ 'Content-Type' = 'application/json' }

    try {
        if ($ApiKey) {
            $script:BHHeaders['Authorization'] = "Bearer $ApiKey"
            $test = Invoke-RestMethod -Uri "$script:BHBaseUrl/api/v2/self" `
                        -Headers $script:BHHeaders -Method GET -ErrorAction Stop
            Write-Log "Connected to BloodHound CE (API Key): $($test.data.principal_name)" -Level SUCCESS -Component BloodHound
            return $true
        }

        if ($Username -and $Password) {
            $cred  = [System.Net.NetworkCredential]::new($Username, $Password)
            $body  = @{ login_username = $cred.UserName; login_secret = $cred.Password } | ConvertTo-Json
            $login = Invoke-RestMethod -Uri "$script:BHBaseUrl/api/v2/login" `
                         -Method POST -Body $body -ContentType 'application/json' -ErrorAction Stop
            $script:BHHeaders['Authorization'] = "Bearer $($login.data.token)"
            Write-Log "Connected to BloodHound CE (credentials)" -Level SUCCESS -Component BloodHound
            return $true
        }

        Write-Log "BloodHound CE: No credentials provided." -Level WARNING -Component BloodHound
        return $false
    } catch {
        Write-Log "Failed to connect to BloodHound CE at $ServerUrl : $_" -Level ERROR -Component BloodHound
        return $false
    }
}

function Connect-BloodHoundEnterprise {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ServerUrl,

        [Parameter(Mandatory)]
        [string]$ApiKey
    )

    $script:BHBaseUrl = $ServerUrl.TrimEnd('/')
    $script:BHEdition = 'Enterprise'
    $script:BHHeaders = @{
        'Content-Type'  = 'application/json'
        'Authorization' = "Bearer $ApiKey"
    }

    try {
        $test = Invoke-RestMethod -Uri "$script:BHBaseUrl/api/v2/self" `
                    -Headers $script:BHHeaders -Method GET -ErrorAction Stop
        Write-Log "Connected to BloodHound Enterprise: $($test.data.principal_name)" -Level SUCCESS -Component BloodHound
        return $true
    } catch {
        Write-Log "Failed to connect to BloodHound Enterprise: $_" -Level ERROR -Component BloodHound
        return $false
    }
}

#endregion

#region Attack Path Retrieval

function Get-BloodHoundAttackPaths {
    [CmdletBinding()]
    param(
        [string]$DomainSID,
        [int]$MaxPaths = 100
    )

    if (-not $script:BHBaseUrl) {
        Write-Log "BloodHound not connected." -Level WARNING -Component BloodHound
        return @()
    }

    $paths = @()

    try {
        # Get shortest paths to Domain Admins
        $paths += Get-BHPathsToGroup -GroupName 'Domain Admins' -DomainSID $DomainSID -MaxPaths $MaxPaths
        $paths += Get-BHPathsToGroup -GroupName 'Enterprise Admins' -DomainSID $DomainSID -MaxPaths $MaxPaths
        $paths += Get-BHPathsToDA -DomainSID $DomainSID
    } catch {
        Write-Log "Error retrieving BloodHound attack paths: $_" -Level ERROR -Component BloodHound
    }

    return $paths
}

function Get-BHPathsToGroup {
    param([string]$GroupName, [string]$DomainSID, [int]$MaxPaths)

    try {
        # Find the group SID first
        $groupSearch = Invoke-RestMethod -Uri "$script:BHBaseUrl/api/v2/search?q=$GroupName&type=Group" `
                           -Headers $script:BHHeaders -Method GET -ErrorAction Stop

        if (-not $groupSearch.data -or $groupSearch.data.Count -eq 0) { return @() }

        $groupId = $groupSearch.data[0].objectid
        $cypher  = "MATCH p=shortestPath((u:User)-[*1..10]->(g:Group {objectid:'$groupId'})) RETURN p LIMIT $MaxPaths"

        $result = Invoke-BHCypher -Query $cypher
        return Convert-BHPaths -RawPaths $result -TargetGroup $GroupName
    } catch {
        Write-Log "Error getting paths to '$GroupName': $_" -Level WARNING -Component BloodHound
        return @()
    }
}

function Get-BHPathsToDA {
    param([string]$DomainSID)

    try {
        # Get paths via DCSync rights
        $cypher = @"
MATCH p=(n)-[:DCSync|AllExtendedRights|GenericAll|WriteDacl]->(d:Domain)
WHERE d.objectid =~ '(?i)$DomainSID'
RETURN p LIMIT 50
"@
        $result = Invoke-BHCypher -Query $cypher
        return Convert-BHPaths -RawPaths $result -TargetGroup 'Domain (DCSync)'
    } catch {
        Write-Log "Error getting DCSync paths: $_" -Level WARNING -Component BloodHound
        return @()
    }
}

function Invoke-BHCypher {
    param([string]$Query)

    $body = @{ query = $Query } | ConvertTo-Json
    $endpoint = if ($script:BHEdition -eq 'Enterprise') { '/api/v2/graphs/cypher' } else { '/api/v2/graphs/cypher' }

    $result = Invoke-RestMethod -Uri "$script:BHBaseUrl$endpoint" `
                  -Headers $script:BHHeaders -Method POST -Body $body -ErrorAction Stop
    return $result
}

function Convert-BHPaths {
    param($RawPaths, [string]$TargetGroup)

    $converted = @()
    if (-not $RawPaths.data) { return $converted }

    foreach ($pathData in $RawPaths.data) {
        try {
            $nodes = @($pathData.nodes)
            $edges = @($pathData.edges)

            $chainParts = @()
            $chainParts += $nodes[0].label
            for ($i = 0; $i -lt $edges.Count; $i++) {
                $chainParts += "--[$($edges[$i].label)]-->"
                $chainParts += $nodes[$i + 1].label
            }

            $converted += [ordered]@{
                Source          = $nodes[0].label
                SourceType      = $nodes[0].kind
                Target          = $TargetGroup
                ChainDisplay    = $chainParts -join ' '
                PathLength      = $edges.Count
                RiskScore       = [Math]::Max(50, 100 - ($edges.Count * 8))
                Severity        = if ($edges.Count -le 3) { 'Critical' } elseif ($edges.Count -le 5) { 'High' } else { 'Medium' }
                DataSource      = 'BloodHound'
                Relationships   = @($edges | ForEach-Object { $_.label })
            }
        } catch { }
    }
    return $converted
}

#endregion

#region Exposure Queries

function Get-BHKerberoastableUsers {
    [CmdletBinding()]
    param()
    if (-not $script:BHBaseUrl) { return @() }
    try {
        $cypher = "MATCH (u:User {hasspn:true, enabled:true}) RETURN u.name, u.samaccountname, u.admincount, u.description LIMIT 500"
        $result = Invoke-BHCypher -Query $cypher
        return @($result.data | ForEach-Object {
            [ordered]@{
                Name           = $_[0]
                SamAccountName = $_[1]
                AdminCount     = $_[2]
                Description    = $_[3]
                DataSource     = 'BloodHound'
            }
        })
    } catch {
        Write-Log "BH Kerberoastable query failed: $_" -Level WARNING -Component BloodHound
        return @()
    }
}

function Get-BHUnconstrainedDelegation {
    [CmdletBinding()]
    param()
    if (-not $script:BHBaseUrl) { return @() }
    try {
        $cypher = "MATCH (c {unconstraineddelegation:true, enabled:true}) WHERE NOT c:Domain RETURN c.name, labels(c), c.samaccountname LIMIT 200"
        $result = Invoke-BHCypher -Query $cypher
        return @($result.data | ForEach-Object {
            [ordered]@{
                Name           = $_[0]
                Type           = $_[1] -join ','
                SamAccountName = $_[2]
                DataSource     = 'BloodHound'
            }
        })
    } catch {
        return @()
    }
}

function Get-BHDomainStats {
    [CmdletBinding()]
    param()
    if (-not $script:BHBaseUrl) { return $null }
    try {
        $result = Invoke-RestMethod -Uri "$script:BHBaseUrl/api/v2/counts" `
                      -Headers $script:BHHeaders -Method GET -ErrorAction Stop
        return $result.data
    } catch {
        Write-Log "BH domain stats query failed: $_" -Level WARNING -Component BloodHound
        return $null
    }
}

#endregion

#region Merge BloodHound + Native Findings

function Merge-BloodHoundFindings {
    [CmdletBinding()]
    param(
        [hashtable]$NativeResults,
        [hashtable]$BloodHoundData,
        [hashtable]$Config
    )

    if (-not $BloodHoundData -or $BloodHoundData.AttackPaths.Count -eq 0) {
        return $NativeResults
    }

    $merged = $NativeResults.Clone()

    # Add BH attack paths that aren't already in native results
    $existingPaths = @($NativeResults.AttackPaths | ForEach-Object { $_.ChainDisplay })

    foreach ($bhPath in $BloodHoundData.AttackPaths) {
        if ($existingPaths -notcontains $bhPath.ChainDisplay) {
            $merged.AttackPaths += $bhPath
        }
    }

    # Enrich native kerberoastable findings with BH context
    foreach ($bhKerb in $BloodHoundData.KerberoastableUsers) {
        $native = $merged.RiskResults.Findings | Where-Object {
            $_.FindingType -eq 'Kerberoasting' -and $_.TargetObject -eq $bhKerb.SamAccountName
        }
        if ($native) {
            $native.BloodHoundEnriched = $true
            $native.BloodHoundData     = $bhKerb
        }
    }

    $merged.BloodHoundIntegrated = $true
    $merged.BloodHoundAttackPaths = $BloodHoundData.AttackPaths.Count

    Write-Log "Merged $($BloodHoundData.AttackPaths.Count) BloodHound attack paths into results." -Level INFO -Component BloodHound
    return $merged
}

#endregion

#region SharpHound / Collector Guidance

function Get-CollectorRunGuidance {
    [CmdletBinding()]
    param([string]$Edition = 'Community')

    return [ordered]@{
        Edition        = $Edition
        CollectorType  = 'SharpHound'
        MinimumVersion = if ($Edition -eq 'Enterprise') { 'BHE Collector v2.0' } else { 'SharpHound 1.1.0' }
        RecommendedCollectionMethods = @(
            'ACL',
            'Group',
            'LocalGroup',
            'ObjectProps',
            'Session',
            'Trusts',
            'Container',
            'GPOLocalGroup',
            'LoggedOn'
        )
        SampleCommand  = @"
# SharpHound Community Edition (run as Domain User minimum)
./SharpHound.exe --CollectionMethods All --ZipFilename bloodhound_$(Get-Date -Format 'yyyyMMdd').zip

# Or with specific methods for lower impact:
./SharpHound.exe --CollectionMethods ACL,Group,ObjectProps,Trusts,Container --ZipFilename bloodhound_acl_$(Get-Date -Format 'yyyyMMdd').zip

# PowerShell version:
Import-Module SharpHound.ps1
Invoke-BloodHound -CollectionMethods All -ZipFilename bloodhound.zip
"@
        SecurityNotes  = @(
            'SharpHound generates significant LDAP traffic - coordinate with security team',
            'Session collection requires admin rights on remote systems',
            'Run during business hours for accurate session data',
            'Store ZIP output securely - contains sensitive AD structure data'
        )
    }
}

#endregion

Export-ModuleMember -Function Connect-BloodHoundCE, Connect-BloodHoundEnterprise,
    Get-BloodHoundAttackPaths, Get-BHKerberoastableUsers, Get-BHUnconstrainedDelegation,
    Get-BHDomainStats, Merge-BloodHoundFindings, Get-CollectorRunGuidance
