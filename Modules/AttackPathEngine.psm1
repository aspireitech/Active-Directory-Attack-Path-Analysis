#Requires -Version 5.1
<#
.SYNOPSIS
    Graph-based attack path analysis engine.
    Performs BFS traversal to discover privilege escalation paths similar to BloodHound.
#>

#region Graph Construction

function Build-ADGraph {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ADData
    )

    # Adjacency list: NodeID -> List of edges
    $graph = @{}
    $nodeMap = @{}

    # Register all nodes
    $registerNode = {
        param([string]$Id, [string]$Label, [string]$Type, [hashtable]$Properties = @{})
        if (-not $graph.ContainsKey($Id)) {
            $graph[$Id]   = [System.Collections.Generic.List[hashtable]]::new()
            $nodeMap[$Id] = [ordered]@{
                Id         = $Id
                Label      = $Label
                Type       = $Type
                Properties = $Properties
            }
        }
    }

    $addEdge = {
        param([string]$From, [string]$To, [string]$Relationship, [int]$Weight = 50)
        if (-not $graph.ContainsKey($From)) {
            $graph[$From] = [System.Collections.Generic.List[hashtable]]::new()
        }
        $graph[$From].Add([ordered]@{
            To           = $To
            Relationship = $Relationship
            Weight       = $Weight
        })
    }

    # --- Users ---
    foreach ($user in $ADData.Users) {
        $id = "user:$($user.SamAccountName)"
        & $registerNode $id $user.SamAccountName 'User' @{
            Enabled          = $user.Enabled
            HasSPN           = $user.HasSPN
            AdminCount       = $user.AdminCount
            TrustedForDeleg  = $user.TrustedForDelegation
            DoesNotReqPreAuth = $user.DoesNotRequirePreAuth
            PasswordNeverExp = $user.PasswordNeverExpires
        }
    }

    # --- Groups ---
    foreach ($group in $ADData.Groups) {
        $gid = "group:$($group.SamAccountName)"
        & $registerNode $gid $group.SamAccountName 'Group' @{
            IsPrivileged = $group.IsPrivileged
            IsTier0      = $group.IsTier0
        }

        # MemberOf edges (group -> parent group)
        foreach ($parentDN in $group.MemberOf) {
            $parentName = ($parentDN -split ',')[0] -replace '^CN=',''
            $parentId   = "group:$parentName"
            & $registerNode $parentId $parentName 'Group' @{}
            & $addEdge $gid $parentId 'MemberOf' 30
        }
    }

    # --- User -> Group Memberships ---
    foreach ($user in $ADData.Users) {
        $uid = "user:$($user.SamAccountName)"
        foreach ($groupDN in $user.MemberOf) {
            $groupName = ($groupDN -split ',')[0] -replace '^CN=',''
            $gid       = "group:$groupName"
            & $registerNode $gid $groupName 'Group' @{}
            & $addEdge $uid $gid 'MemberOf' 10
        }
    }

    # --- ACL Edges ---
    foreach ($acl in $ADData.ACLFindings) {
        $sourceId = Resolve-NodeId -Identity $acl.SourceIdentity -NodeMap $nodeMap
        $targetId = Resolve-NodeId -Identity $acl.TargetObject -NodeMap $nodeMap

        if ($sourceId -and $targetId) {
            $weight = switch ($acl.FindingType) {
                'DCSyncRight'  { 95 }
                'GenericAll'   { 85 }
                'GenericWrite' { 75 }
                'WriteDACL'    { 70 }
                'WriteOwner'   { 65 }
                default        { 50 }
            }
            & $addEdge $sourceId $targetId $acl.FindingType $weight
        }
    }

    # --- Kerberoastable Edges ---
    foreach ($account in $ADData.KerberoastableAccounts) {
        $uid = "user:$($account.SamAccountName)"
        & $addEdge 'attacker:any_auth_user' $uid 'CanKerberoast' 50
        & $registerNode 'attacker:any_auth_user' 'Any Authenticated User' 'Attacker' @{}
    }

    # --- AS-REP Edges ---
    foreach ($account in $ADData.ASREPRoastableAccounts) {
        $uid = "user:$($account.SamAccountName)"
        & $addEdge 'attacker:unauthenticated' $uid 'CanASREPRoast' 50
        & $registerNode 'attacker:unauthenticated' 'Unauthenticated Attacker' 'Attacker' @{}
    }

    # --- Delegation Edges ---
    foreach ($finding in $ADData.DelegationFindings) {
        $oid = "computer:$($finding.ObjectName)"
        if ($finding.ObjectType -eq 'User') { $oid = "user:$($finding.ObjectName)" }
        & $registerNode $oid $finding.ObjectName $finding.ObjectType @{}
        $weight = switch ($finding.Type) {
            'UnconstrainedDelegation'         { 82 }
            'ConstrainedDelegationAnyProtocol'{ 60 }
            'ConstrainedDelegation'           { 50 }
            'ResourceBasedConstrainedDelegation' { 58 }
            default { 40 }
        }
        & $addEdge $oid 'tier0:domain_controllers' $finding.Type $weight
        & $registerNode 'tier0:domain_controllers' 'Domain Controllers' 'Tier0' @{ IsTier0 = $true }
    }

    # --- DCSync Edges ---
    foreach ($account in $ADData.DCSyncAccounts) {
        $sid = Resolve-NodeId -Identity $account.Identity -NodeMap $nodeMap
        if (-not $sid) {
            $sid = "identity:$($account.Identity)"
            & $registerNode $sid $account.Identity 'Identity' @{}
        }
        & $addEdge $sid 'tier0:domain' 'DCSync' 95
        & $registerNode 'tier0:domain' 'Domain Object' 'Tier0' @{ IsTier0 = $true }
    }

    # --- Privileged Group Membership Edges ---
    foreach ($pg in $ADData.PrivilegedGroups) {
        $gid = "group:$($pg.Name)"
        & $registerNode $gid $pg.Name 'Group' @{ IsPrivileged = $true; IsTier0 = $pg.IsTier0 }
        foreach ($memberName in $pg.NestedMembers) {
            $mid = "user:$memberName"
            & $registerNode $mid $memberName 'User' @{}
            & $addEdge $mid $gid 'NestedMemberOf' 20
        }
    }

    return [ordered]@{
        Graph   = $graph
        NodeMap = $nodeMap
    }
}

function Resolve-NodeId {
    param([string]$Identity, [hashtable]$NodeMap)
    # Try exact match first
    if ($NodeMap.ContainsKey("user:$Identity"))     { return "user:$Identity"     }
    if ($NodeMap.ContainsKey("group:$Identity"))    { return "group:$Identity"    }
    if ($NodeMap.ContainsKey("computer:$Identity")) { return "computer:$Identity" }
    # Partial match by label
    foreach ($key in $NodeMap.Keys) {
        if ($NodeMap[$key].Label -eq $Identity) { return $key }
    }
    # Try extracting CN from DN
    if ($Identity -match '^CN=([^,]+)') {
        $cn = $Matches[1]
        if ($NodeMap.ContainsKey("user:$cn"))    { return "user:$cn"    }
        if ($NodeMap.ContainsKey("group:$cn"))   { return "group:$cn"   }
    }
    return $null
}

#endregion

#region BFS Attack Path Finder

function Find-AttackPaths {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$GraphData,

        [hashtable]$Config,

        [string[]]$HighValueTargets = @(
            'group:Domain Admins',
            'group:Enterprise Admins',
            'group:Schema Admins',
            'group:Administrators',
            'tier0:domain',
            'tier0:domain_controllers'
        )
    )

    $maxDepth  = $Config.Analysis.MaxAttackPathDepth
    $graph     = $GraphData.Graph
    $nodeMap   = $GraphData.NodeMap
    $allPaths  = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($target in $HighValueTargets) {
        if (-not $graph.ContainsKey($target) -and -not $nodeMap.ContainsKey($target)) { continue }

        # BFS from all user nodes toward the target
        $userNodes = @($nodeMap.Keys | Where-Object { $_ -like 'user:*' -or $_ -like 'attacker:*' })

        foreach ($startNode in $userNodes) {
            if ($startNode -eq $target) { continue }

            $paths = Find-PathsBFS -Graph $graph -NodeMap $nodeMap `
                                   -Start $startNode -Target $target -MaxDepth $maxDepth

            foreach ($path in $paths) {
                if ($path.Count -lt 2) { continue }

                $pathScore    = Calculate-PathRiskScore -Path $path -NodeMap $nodeMap
                $pathSeverity = Get-PathSeverity -TargetId $target -PathScore $pathScore

                $allPaths.Add([ordered]@{
                    PathId          = [System.Guid]::NewGuid().ToString()
                    SourceNode      = $startNode
                    SourceLabel     = $nodeMap[$startNode].Label
                    TargetNode      = $target
                    TargetLabel     = if ($nodeMap.ContainsKey($target)) { $nodeMap[$target].Label } else { $target }
                    PathChain       = $path
                    PathLength      = $path.Count - 1
                    RiskScore       = $pathScore
                    Severity        = $pathSeverity
                    ChainDisplay    = Format-PathChain -Path $path -NodeMap $nodeMap
                    MitreMapping    = Get-PathMitreMapping -TargetId $target
                    ExploitSteps    = Get-PathExploitSteps -Path $path -NodeMap $nodeMap
                    Remediation     = Get-PathRemediation -Path $path -NodeMap $nodeMap -Target $target
                    RemediationRisk = 'Medium'
                })
            }
        }
    }

    # Deduplicate and sort by score descending
    $unique = $allPaths | Sort-Object { $_.RiskScore } -Descending |
              Group-Object { "$($_.SourceNode)|$($_.TargetNode)|$($_.PathLength)" } |
              ForEach-Object { $_.Group[0] }

    return @($unique)
}

function Find-PathsBFS {
    param(
        [hashtable]$Graph,
        [hashtable]$NodeMap,
        [string]$Start,
        [string]$Target,
        [int]$MaxDepth = 10
    )

    $results = [System.Collections.Generic.List[string[]]]::new()
    $queue   = [System.Collections.Generic.Queue[System.Collections.Generic.List[string]]]::new()
    $initial = [System.Collections.Generic.List[string]]::new()
    $initial.Add($Start)
    $queue.Enqueue($initial)

    $visited = [System.Collections.Generic.HashSet[string]]::new()

    while ($queue.Count -gt 0) {
        $currentPath = $queue.Dequeue()
        $currentNode = $currentPath[$currentPath.Count - 1]

        if ($currentPath.Count -gt $MaxDepth + 1) { continue }
        if ($visited.Contains("$($currentPath[0])|$currentNode")) { continue }
        $null = $visited.Add("$($currentPath[0])|$currentNode")

        if ($currentNode -eq $Target) {
            $results.Add($currentPath.ToArray())
            continue
        }

        if (-not $Graph.ContainsKey($currentNode)) { continue }

        foreach ($edge in $Graph[$currentNode]) {
            if ($currentPath -notcontains $edge.To) {
                $newPath = [System.Collections.Generic.List[string]]::new($currentPath)
                $newPath.Add($edge.To)
                $queue.Enqueue($newPath)
            }
        }
    }

    return $results
}

#endregion

#region Path Scoring and Formatting

function Calculate-PathRiskScore {
    param([string[]]$Path, [hashtable]$NodeMap)

    $baseScore = 100 - ($Path.Count * 5) # Shorter paths are riskier

    foreach ($nodeId in $Path) {
        if (-not $NodeMap.ContainsKey($nodeId)) { continue }
        $node = $NodeMap[$nodeId]
        if ($node.Properties.IsTier0)      { $baseScore += 20 }
        if ($node.Properties.IsPrivileged) { $baseScore += 10 }
        if ($node.Properties.AdminCount -eq 1) { $baseScore += 10 }
    }

    return [Math]::Min(100, [Math]::Max(10, $baseScore))
}

function Get-PathSeverity {
    param([string]$TargetId, [int]$PathScore)
    if ($TargetId -match 'Domain Admins|Enterprise Admins|Schema Admins|tier0') {
        if ($PathScore -ge 70) { return 'Critical' }
        return 'High'
    }
    if ($PathScore -ge 90) { return 'Critical' }
    if ($PathScore -ge 70) { return 'High'     }
    if ($PathScore -ge 40) { return 'Medium'   }
    return 'Low'
}

function Format-PathChain {
    param([string[]]$Path, [hashtable]$NodeMap)

    $parts = foreach ($nodeId in $Path) {
        $label = if ($NodeMap.ContainsKey($nodeId)) { $NodeMap[$nodeId].Label } else { $nodeId }
        $type  = if ($NodeMap.ContainsKey($nodeId)) { $NodeMap[$nodeId].Type  } else { 'Unknown' }
        "[$type] $label"
    }
    return $parts -join ' → '
}

function Get-PathMitreMapping {
    param([string]$TargetId)
    if ($TargetId -match 'Domain Admins|tier0:domain$') {
        return @{ ID = 'T1078.002'; Name = 'Domain Account Takeover'; Tactic = 'Privilege Escalation' }
    }
    if ($TargetId -match 'Enterprise Admins') {
        return @{ ID = 'T1078.002'; Name = 'Enterprise Admin Access'; Tactic = 'Privilege Escalation' }
    }
    if ($TargetId -match 'DCSync|domain_controllers') {
        return @{ ID = 'T1003.006'; Name = 'DCSync'; Tactic = 'Credential Access' }
    }
    return @{ ID = 'T1078.002'; Name = 'Valid Accounts'; Tactic = 'Privilege Escalation' }
}

function Get-PathExploitSteps {
    param([string[]]$Path, [hashtable]$NodeMap)

    $steps = [System.Collections.Generic.List[string]]::new()
    for ($i = 0; $i -lt ($Path.Count - 1); $i++) {
        $fromId = $Path[$i]
        $toId   = $Path[$i+1]
        $fromLabel = if ($NodeMap.ContainsKey($fromId)) { $NodeMap[$fromId].Label } else { $fromId }
        $toLabel   = if ($NodeMap.ContainsKey($toId))   { $NodeMap[$toId].Label   } else { $toId   }
        $toType    = if ($NodeMap.ContainsKey($toId))   { $NodeMap[$toId].Type    } else { 'Unknown' }

        # Find the relationship
        $rel = 'Access'
        if ($NodeMap[$fromId]?.Properties.HasSPN) { $rel = 'Kerberoast → Crack Ticket' }
        elseif ($toType -eq 'Group')              { $rel = 'GroupMembership → Inherit Privileges' }
        elseif ($toType -eq 'Tier0')              { $rel = 'Escalate → Tier-0 Control' }

        $steps.Add("Step $($i+1): Compromise '$fromLabel' → pivot to '$toLabel' ($rel)")
    }
    return @($steps)
}

function Get-PathRemediation {
    param([string[]]$Path, [hashtable]$NodeMap, [string]$Target)

    $remediations = [System.Collections.Generic.List[string]]::new()

    # Identify the weakest link (easiest to fix)
    foreach ($nodeId in $Path) {
        if (-not $NodeMap.ContainsKey($nodeId)) { continue }
        $node = $NodeMap[$nodeId]

        if ($node.Properties.HasSPN) {
            $remediations.Add("Convert '$($node.Label)' to a Group Managed Service Account (gMSA) to eliminate Kerberoastable SPN.")
        }
        if ($node.Properties.DoesNotReqPreAuth) {
            $remediations.Add("Enable Kerberos pre-authentication on '$($node.Label)': Set-ADAccountControl -DoesNotRequirePreAuth `$false")
        }
        if ($node.Properties.TrustedForDeleg) {
            $remediations.Add("Remove unconstrained delegation from '$($node.Label)': Set-ADComputer -TrustedForDelegation `$false")
        }
    }

    if ($remediations.Count -eq 0) {
        $remediations.Add("Break the attack path by removing unnecessary group memberships or ACE rights along the chain.")
        $remediations.Add("Implement AD Tiering model to structurally prevent cross-tier access paths.")
    }

    return @($remediations)
}

#endregion

#region Path Statistics

function Get-AttackPathStats {
    param([hashtable[]]$AttackPaths)

    return [ordered]@{
        TotalPaths         = $AttackPaths.Count
        CriticalPaths      = @($AttackPaths | Where-Object { $_.Severity -eq 'Critical' }).Count
        HighPaths          = @($AttackPaths | Where-Object { $_.Severity -eq 'High'     }).Count
        MediumPaths        = @($AttackPaths | Where-Object { $_.Severity -eq 'Medium'   }).Count
        ShortestPath       = if ($AttackPaths.Count -gt 0) { ($AttackPaths | Measure-Object -Property PathLength -Minimum).Minimum } else { 0 }
        AveragePathLength  = if ($AttackPaths.Count -gt 0) { [Math]::Round(($AttackPaths | Measure-Object -Property PathLength -Average).Average, 1) } else { 0 }
        UniqueSourceNodes  = @($AttackPaths | Select-Object -ExpandProperty SourceNode -Unique).Count
        UniqueTargetNodes  = @($AttackPaths | Select-Object -ExpandProperty TargetNode -Unique).Count
        TopSourceNodes     = @($AttackPaths | Group-Object SourceLabel | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object { "$($_.Name) ($($_.Count) paths)" })
    }
}

#endregion

Export-ModuleMember -Function Build-ADGraph, Find-AttackPaths, Get-AttackPathStats,
    Find-PathsBFS, Format-PathChain, Calculate-PathRiskScore
