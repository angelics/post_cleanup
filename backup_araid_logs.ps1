$log = "$env:SystemRoot\araid\araid_post.log"

$logDirectory = Split-Path -Path $log -Parent
if (!(Test-Path $logDirectory)) {
    New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
}

Function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [string]$Color = "White"
    )

    try {
        $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Add-Content -Path $log -Value "[$timestamp] $Message"
        Write-Host $Message -ForegroundColor $Color
    } catch {
        Write-Host "Failed to write log: $_" -ForegroundColor Red
    }
}

# shortcut: mirror copy of Backup-AraidLogFolder in post_cleanup_update.ps1; update both together.
function Backup-AraidLogFolder {
    $source = Split-Path -Path $log -Parent
    if (-not (Test-Path -Path $source -PathType Container)) {
        Write-Log "Log folder not found; backup skipped: $source" "Yellow"
        return
    }

    # Recovery partition created by diskpart: Windows RE type GUID + label "Recovery".
    $partition = Get-Partition -ErrorAction SilentlyContinue |
        Where-Object { ($_.GptType -replace '[{}]', '') -eq 'de94bba4-06d1-4d40-a16a-bfd50179d6ac' } |
        Select-Object -First 1

    if (-not $partition) {
        Write-Log "Recovery partition not found; log backup skipped." "Yellow"
        return
    }

    # Recovery partitions have no letter by default; borrow one, then release it.
    $letter = if ($partition.DriveLetter) {
        [string]$partition.DriveLetter
    } else {
        $used = @(Get-PSDrive -PSProvider FileSystem | Select-Object -ExpandProperty Name)
        @('R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z') |
            Where-Object { $_ -notin $used } |
            Select-Object -First 1
    }

    if (-not $letter) {
        Write-Log "No free drive letter for Recovery backup; skipped." "Yellow"
        return
    }

    $accessPath = "${letter}:\"
    $destination = "${accessPath}araid"
    $assigned = $false

    try {
        if (-not $partition.DriveLetter) {
            Set-Partition -DiskNumber $partition.DiskNumber -PartitionNumber $partition.PartitionNumber -NewDriveLetter $letter -ErrorAction Stop
            $assigned = $true
        }

        if ($destination -notmatch '^[A-Z]:\\araid$') {
            throw "Unsafe backup destination: $destination"
        }

        if (Test-Path -Path $destination) {
            Remove-Item -Path $destination -Recurse -Force -ErrorAction Stop
        }
        New-Item -ItemType Directory -Path $destination -Force -ErrorAction Stop | Out-Null
        Copy-Item -Path (Join-Path $source '*') -Destination $destination -Recurse -Force -ErrorAction Stop
        Write-Log "Mirrored $source to $destination"
    } catch {
        Write-Log "Log backup failed: $_" "Yellow"
    } finally {
        if ($assigned) {
            try {
                Remove-PartitionAccessPath -DiskNumber $partition.DiskNumber -PartitionNumber $partition.PartitionNumber -AccessPath $accessPath -ErrorAction Stop
            } catch {
                Write-Log "Failed to release Recovery drive letter ${letter}: $_" "Yellow"
            }
        }
    }
}

Backup-AraidLogFolder
