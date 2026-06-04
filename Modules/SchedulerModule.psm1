#Requires -Version 5.1
<#
.SYNOPSIS
    Windows Task Scheduler integration module.
    Registers, removes, and manages scheduled execution of the platform.
#>

function Install-ADAttackPathSchedule {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$ScriptPath,

        [Parameter(Mandatory)]
        [string]$ConfigPath,

        [ValidateSet('Weekly','Daily','Hourly','Manual')]
        [string]$Frequency = 'Weekly',

        [ValidateSet('Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday')]
        [string]$DayOfWeek = 'Monday',

        [string]$TimeOfDay = '06:00',

        [string]$RunAsUser = 'SYSTEM',

        [string]$TaskName  = 'AD-AttackPath-WeeklyReport',
        [string]$TaskPath  = '\SecurityAutomation\'
    )

    if (-not (Test-Path $ScriptPath)) {
        throw "Script not found: $ScriptPath"
    }
    if (-not (Test-Path $ConfigPath)) {
        throw "Config not found: $ConfigPath"
    }

    $action   = New-ScheduledTaskAction `
        -Execute 'powershell.exe' `
        -Argument "-NonInteractive -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$ScriptPath`" -ConfigPath `"$ConfigPath`" -AutoRun"

    $settings = New-ScheduledTaskSettingsSet `
        -ExecutionTimeLimit (New-TimeSpan -Hours 4) `
        -StartWhenAvailable `
        -RunOnlyIfNetworkAvailable `
        -RestartCount 2 `
        -RestartInterval (New-TimeSpan -Minutes 30) `
        -MultipleInstances IgnoreNew

    $principal = if ($RunAsUser -eq 'SYSTEM') {
        New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    } else {
        New-ScheduledTaskPrincipal -UserId $RunAsUser -LogonType Password -RunLevel Highest
    }

    $trigger = switch ($Frequency) {
        'Weekly'  {
            $time = [datetime]::ParseExact($TimeOfDay, 'HH:mm', $null)
            New-ScheduledTaskTrigger -Weekly -DaysOfWeek $DayOfWeek -At $time
        }
        'Daily'   {
            $time = [datetime]::ParseExact($TimeOfDay, 'HH:mm', $null)
            New-ScheduledTaskTrigger -Daily -At $time
        }
        'Hourly'  {
            New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Hours 1) -Once -At (Get-Date)
        }
        'Manual'  { $null }
    }

    # Remove existing task if present
    $existing = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
    if ($existing) {
        if ($PSCmdlet.ShouldProcess($TaskName, 'Remove existing scheduled task')) {
            Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Confirm:$false
        }
    }

    $params = @{
        TaskName  = $TaskName
        TaskPath  = $TaskPath
        Action    = $action
        Settings  = $settings
        Principal = $principal
        Force     = $true
    }
    if ($trigger) { $params.Trigger = $trigger }

    if ($PSCmdlet.ShouldProcess($TaskName, 'Register scheduled task')) {
        $task = Register-ScheduledTask @params
        Write-Log "Scheduled task registered: $TaskPath$TaskName ($Frequency)" -Level SUCCESS -Component Scheduler
        return $task
    }
}

function Remove-ADAttackPathSchedule {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$TaskName = 'AD-AttackPath-WeeklyReport',
        [string]$TaskPath = '\SecurityAutomation\'
    )

    $task = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
    if (-not $task) {
        Write-Log "Scheduled task '$TaskPath$TaskName' not found." -Level WARNING -Component Scheduler
        return
    }

    if ($PSCmdlet.ShouldProcess($TaskName, 'Remove scheduled task')) {
        Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Confirm:$false
        Write-Log "Scheduled task removed: $TaskPath$TaskName" -Level SUCCESS -Component Scheduler
    }
}

function Get-ADAttackPathScheduleStatus {
    [CmdletBinding()]
    param(
        [string]$TaskName = 'AD-AttackPath-WeeklyReport',
        [string]$TaskPath = '\SecurityAutomation\'
    )

    $task = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
    if (-not $task) {
        return [ordered]@{
            IsInstalled = $false
            TaskName    = $TaskName
        }
    }

    $info = Get-ScheduledTaskInfo -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue

    return [ordered]@{
        IsInstalled     = $true
        TaskName        = $TaskName
        TaskPath        = $TaskPath
        State           = $task.State.ToString()
        LastRunTime     = $info.LastRunTime
        NextRunTime     = $info.NextRunTime
        LastResult      = $info.LastTaskResult
        LastResultHex   = '0x{0:X8}' -f $info.LastTaskResult
        RunAs           = $task.Principal.UserId
        Triggers        = @($task.Triggers | ForEach-Object { $_.ToString() })
    }
}

function Invoke-ADAttackPathNow {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$TaskName = 'AD-AttackPath-WeeklyReport',
        [string]$TaskPath = '\SecurityAutomation\'
    )

    $task = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
    if (-not $task) {
        Write-Log "Cannot run: task '$TaskPath$TaskName' not registered." -Level ERROR -Component Scheduler
        return $false
    }

    if ($PSCmdlet.ShouldProcess($TaskName, 'Start scheduled task')) {
        Start-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath
        Write-Log "Task '$TaskPath$TaskName' started on-demand." -Level SUCCESS -Component Scheduler
        return $true
    }
}

Export-ModuleMember -Function Install-ADAttackPathSchedule, Remove-ADAttackPathSchedule,
    Get-ADAttackPathScheduleStatus, Invoke-ADAttackPathNow
