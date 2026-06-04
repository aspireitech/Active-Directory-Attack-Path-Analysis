#Requires -Version 5.1
<#
.SYNOPSIS
    Logging module for the AD Attack Path Analysis Platform.
#>

$script:LogPath = $null
$script:LogLevel = 'INFO'
$script:LogLevels = @{ DEBUG = 0; INFO = 1; SUCCESS = 2; WARNING = 3; ERROR = 4; CRITICAL = 5 }

function Initialize-Logger {
    [CmdletBinding()]
    param(
        [string]$LogDirectory,
        [string]$LogFileName,
        [ValidateSet('DEBUG','INFO','SUCCESS','WARNING','ERROR','CRITICAL')]
        [string]$MinLevel = 'INFO'
    )

    if (-not (Test-Path $LogDirectory)) {
        New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
    }

    if (-not $LogFileName) {
        $LogFileName = "ADAttackPath_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    }

    $script:LogPath  = Join-Path $LogDirectory $LogFileName
    $script:LogLevel = $MinLevel

    Write-Log -Message "Logger initialized. Log file: $($script:LogPath)" -Level INFO
}

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$Message,

        [ValidateSet('DEBUG','INFO','SUCCESS','WARNING','ERROR','CRITICAL')]
        [string]$Level = 'INFO',

        [string]$Component = 'Platform',

        [switch]$NoConsole
    )

    process {
        $currentLevelValue  = $script:LogLevels[$script:LogLevel]
        $messageLevelValue  = $script:LogLevels[$Level]

        if ($messageLevelValue -lt $currentLevelValue) { return }

        $timestamp  = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        $logEntry   = "[$timestamp] [$Level] [$Component] $Message"

        if ($script:LogPath) {
            try { Add-Content -Path $script:LogPath -Value $logEntry -Encoding UTF8 }
            catch { Write-Warning "Failed to write to log file: $_" }
        }

        if (-not $NoConsole) {
            $color = switch ($Level) {
                'DEBUG'    { 'Gray'    }
                'INFO'     { 'Cyan'    }
                'SUCCESS'  { 'Green'   }
                'WARNING'  { 'Yellow'  }
                'ERROR'    { 'Red'     }
                'CRITICAL' { 'Magenta' }
                default    { 'White'   }
            }
            Write-Host $logEntry -ForegroundColor $color
        }
    }
}

function Get-LogPath {
    return $script:LogPath
}

function Write-LogSeparator {
    param([string]$Title = '')
    $line = '=' * 80
    Write-Log -Message $line          -Level INFO -NoConsole
    if ($Title) {
        Write-Log -Message "  $Title" -Level INFO -NoConsole
        Write-Log -Message $line      -Level INFO -NoConsole
    }
}

Export-ModuleMember -Function Initialize-Logger, Write-Log, Get-LogPath, Write-LogSeparator
