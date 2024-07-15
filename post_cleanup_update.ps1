$log = "C:\Windows\Logs\araid\araid_post.log"
$newLog = "C:\Windows\Logs\post.log"

# Check if the original log file exists
if (Test-Path -Path $log -PathType Leaf) {
    # Get the directory of the original log file
    $logDirectory = Split-Path -Path $log -Parent

    # Check if the log directory exists, if not, create it
    if (-not (Test-Path -Path $logDirectory -PathType Container)) {
        New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
        Write-Host "Created log directory: $logDirectory"
    }

    # Delete the existing log file
    Remove-Item -Path $log -Force
    Write-Host "Deleted existing log file: $log"
} else {
    # Change log file path to the new log file path
    $log = $newLog
    Write-Host "Changed log file path to: $log"
}

# Function to log messages to the specified log file
function Write-Log {
    param(
        [string]$Message
    )
    Add-Content -Path $log -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message"
}

taskkill /f /im explorer.exe
Write-Log "Task killed: explorer.exe"

# https://gist.githubusercontent.com/mark05e/745afaf5604487b804ede2cdc38a977f/raw/95f5a609972cff862ce3d92ac4c2b918d37de1c1/DriveClean.ps1
# https://github.com/inode64/WindowsClearCache
#------------------------------------------------------------------#
#- Clear-GlobalWindowsCache                                        #
#------------------------------------------------------------------#
Function Clear-GlobalWindowsCache
{
    Remove-Dir "C:\Windows\Temp"
    Remove-Dir "C:\Temp"
    Remove-Dir "C:\tmp"
    Remove-Dir "C:\$Recycle.Bin"
    Remove-Dir "C:\Windows\Prefetch"
    C:\Windows\System32\rundll32.exe InetCpl.cpl, ClearMyTracksByProcess 4351

}

#------------------------------------------------------------------#
#- Clear-UserCacheFiles                                            #
#------------------------------------------------------------------#
Function Clear-UserCacheFiles
{
    # Stop-BrowserSessions
    ForEach ($localUser in (Get-ChildItem "C:\users").Name)
    {
		Clear-AcrobatCacheFiles $localUser
        Clear-ChromeCacheFiles $localUser
        Clear-DiscordCacheFiles $localUser
        Clear-EdgeCacheFiles $localUser
        Clear-FirefoxCacheFiles $localUser
        Clear-MicrosoftOfficeCacheFiles $localUser
        Clear-SteamCacheFiles $localUser
        Clear-TeamsCacheFiles $localUser
        Clear-WindowsUserCacheFiles $localUser
    }
}

#------------------------------------------------------------------#
#- Clear-WindowsUserCacheFiles                                     #
#------------------------------------------------------------------#
Function Clear-WindowsUserCacheFiles
{
    param([string]$user = $env:USERNAME)
    Remove-Dir "C:\Users\$user\AppData\Local\Microsoft\Internet Explorer\Cache"
    Remove-Dir "C:\Users\$user\AppData\Local\Microsoft\Internet Explorer\Recovery"
    Remove-Dir "C:\Users\$user\AppData\Local\Microsoft\Internet Explorer\Tiles"
    Remove-Dir "C:\Users\$user\AppData\Local\Microsoft\Terminal Server Client\Cache"
    Remove-Dir "C:\Users\$user\AppData\Local\Microsoft\Windows\Caches"
    Remove-Dir "C:\Users\$user\AppData\Local\Microsoft\Windows\History\low"
    Remove-Dir "C:\Users\$user\AppData\Local\Microsoft\Windows\IECompatCache"
    Remove-Dir "C:\Users\$user\AppData\Local\Microsoft\Windows\IECompatUaCache"
    Remove-Dir "C:\Users\$user\AppData\Local\Microsoft\Windows\IEDownloadHistory"
    Remove-Dir "C:\Users\$user\AppData\Local\Microsoft\Windows\INetCache"
    Remove-Dir "C:\Users\$user\AppData\Local\Microsoft\Windows\Temporary Internet Files"
    Remove-Dir "C:\Users\$user\AppData\Local\Microsoft\Windows\WebCache"
    Remove-Dir "C:\Users\$user\AppData\Local\Microsoft\Windows\WER"
    Remove-Dir "C:\Users\$user\AppData\Local\Temp"
}

#------------------------------------------------------------------#
#- Stop-BrowserSessions                                            #
#------------------------------------------------------------------#
Function Stop-BrowserSessions
{
    $activeBrowsers = Get-Process Firefox*, Chrome*, Edge*
    ForEach ($browserProcess in $activeBrowsers)
    {
        try
        {
            $browserProcess.CloseMainWindow() | Out-Null
        }
        catch
        {
        }
    }
}

#------------------------------------------------------------------#
#- Remove-Dir                                               #
#------------------------------------------------------------------#
Function Remove-Dir
{
    param([Parameter(Mandatory = $true)][string]$path)

    if ((Test-Path "$path"))
    {
        Get-ChildItem -Path "$path" -Force -Recurse -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
		Write-Log "directory removed $path"
    }
}

#------------------------------------------------------------------#
#- Clear-ChromeTemplate                                            #
#------------------------------------------------------------------#
Function Clear-ChromeTemplate
{
    param(
        [Parameter(Mandatory = $true)][string]$path,
        [Parameter(Mandatory = $true)][string]$name
    )

    if ((Test-Path $path))
    {
        Write-Output "Clear cache $name"
        $possibleCachePaths = @("Cache", "Cache2\entries\", "ChromeDWriteFontCache", "Code Cache", "GPUCache", "JumpListIcons", "JumpListIconsOld", "Media Cache", "Service Worker", "Top Sites", "VisitedLinks", "Web Data")
        ForEach ($cachePath in $possibleCachePaths)
        {
            Remove-Dir "$path\$cachePath"
        }
    }
}

#------------------------------------------------------------------#
#- Clear-MozillaTemplate                                           #
#------------------------------------------------------------------#
Function Clear-MozillaTemplate
{
    param(
        [Parameter(Mandatory = $true)][string]$path,
        [Parameter(Mandatory = $true)][string]$name
    )

    if ((Test-Path $path))
    {
        Write-Output "Clear cache $name"
        $AppDataPath = (Get-ChildItem "$path" | Where-Object { $_.Name -match "Default" }[0]).FullName
        $possibleCachePaths = @("cache", "cache2\entries", "thumbnails", "webappsstore.sqlite", "chromeappstore.sqlite")
        ForEach ($cachePath in $possibleCachePaths)
        {
            Remove-Dir "$AppDataPath\$cachePath"
        }
    }
}


#------------------------------------------------------------------#
#- Clear-ChromeCache                                               #
#------------------------------------------------------------------#
Function Clear-ChromeCacheFiles
{
    param([string]$user = $env:USERNAME)
    Clear-ChromeTemplate "C:\users\$user\AppData\Local\Google\Chrome\User Data\Default" "Browser Google Chrome"
    Remove-Dir "C:\users\$user\AppData\Local\Google\Chrome\User Data\SwReporter\"
}

#------------------------------------------------------------------#
#- Clear-EdgeCache                                                 #
#------------------------------------------------------------------#
Function Clear-EdgeCacheFiles
{
    param([string]$user = $env:USERNAME)
    Clear-ChromeTemplate "C:\users\$user\AppData\Local\Microsoft\Edge\User Data\Default" "Browser Microsoft Edge"
    Remove-Dir "C:\users\$user\AppData\Local\Microsoft\Edge\User Data\Default\CacheStorage"
}

#------------------------------------------------------------------#
#- Clear-FirefoxCacheFiles                                         #
#------------------------------------------------------------------#
Function Clear-FirefoxCacheFiles
{
    param([string]$user = $env:USERNAME)
    Clear-MozillaTemplate "C:\users\$user\AppData\Local\Mozilla\Firefox\Profiles" "Browser Mozilla Firefox"
}

#------------------------------------------------------------------#
#- Clear-SteamCacheFiles                                     #
#------------------------------------------------------------------#
Function Clear-SteamCacheFiles
{
    param([string]$user = $env:USERNAME)
    Clear-ChromeTemplate "C:\users\$user\AppData\Local\Steam\htmlcache" "Steam"
}

#------------------------------------------------------------------#
#- Clear-DiscordCacheFiles                                     #
#------------------------------------------------------------------#
Function Clear-DiscordCacheFiles
{
    param([string]$user = $env:USERNAME)
    Clear-ChromeTemplate "C:\users\$user\AppData\Local\Discord" "Discord"
}

#------------------------------------------------------------------#
#- Clear-AcrobatCacheFiles                                     #
#------------------------------------------------------------------#
Function Clear-AcrobatCacheFiles
{
    param([string]$user = $env:USERNAME)
    $DirName = "C:\users\$user\AppData\LocalLow\Adobe\Acrobat"
    if ((Test-Path "$DirName"))
    {
        $possibleCachePaths = @("Cache", "ConnectorIcons")
        ForEach ($AcrobatAppDataPath in (Get-ChildItem "$DirName").Name)
        {
            ForEach ($cachePath in $possibleCachePaths)
            {
                Remove-Dir "$DirName\$AcrobatAppDataPath\$cachePath"
            }
        }
    }
}

#------------------------------------------------------------------#
#- Clear-TeamsCacheFiles                                           #
#------------------------------------------------------------------#
Function Clear-TeamsCacheFiles
{
    param([string]$user = $env:USERNAME)
    if ((Test-Path "C:\users\$user\AppData\Roaming\Microsoft\Teams"))
    {
        $possibleCachePaths = @("application cache\cache", "blob_storage", "Cache", "Code Cache", "GPUCache", "logs", "tmp", "Service Worker\CacheStorage", "Service Worker\ScriptCache")
        $teamsAppDataPath = "C:\users\$user\AppData\Roaming\Microsoft\Teams"
        ForEach ($cachePath in $possibleCachePaths)
        {
            Remove-Dir "$teamsAppDataPath\$cachePath"
        }
    }
}

#------------------------------------------------------------------#
#- Clear-MicrosoftOfficeCacheFiles                                 #
#------------------------------------------------------------------#
Function Clear-MicrosoftOfficeCacheFiles
{
    param([string]$user = $env:USERNAME)
    if ((Test-Path "C:\users\$user\AppData\Local\Microsoft\Outlook"))
    {
        Get-ChildItem "C:\users\$user\AppData\Local\Microsoft\Outlook\*.pst" -Recurse -Force -ErrorAction SilentlyContinue |
                remove-item -force -recurse -ErrorAction SilentlyContinue -Verbose
        Get-ChildItem "C:\users\$user\AppData\Local\Microsoft\Outlook\*.ost" -Recurse -Force -ErrorAction SilentlyContinue |
                remove-item -force -recurse -ErrorAction SilentlyContinue -Verbose
        Get-ChildItem "C:\users\$user\AppData\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook\*" -Recurse -Force -ErrorAction SilentlyContinue |
                remove-item -force -recurse -ErrorAction SilentlyContinue -Verbose
        Get-ChildItem "C:\users\$user\AppData\Local\Microsoft\Windows\Temporary Internet Files\Content.MSO\*" -Recurse -Force -ErrorAction SilentlyContinue |
                remove-item -force -recurse -ErrorAction SilentlyContinue -Verbose
        Get-ChildItem "C:\users\$user\AppData\Local\Microsoft\Windows\Temporary Internet Files\Content.Word\*" -Recurse -Force -ErrorAction SilentlyContinue |
                remove-item -force -recurse -ErrorAction SilentlyContinue -Verbose
    }
}

Write-Output "y" | winget upgrade
winget pin add --id Discord.Discord --blocking
Write-Log "winget pin Discord.Discord"
Start-Sleep -Seconds 1
winget pin add --id Microsoft.DevHome --blocking
Write-Log "winget pin Microsoft.DevHome"
Start-Sleep -Seconds 1
winget pin add --id Cisco.Webex --blocking
Write-Log "winget pin Cisco.Webex"
Start-Sleep -Seconds 1
winget upgrade --all --accept-package-agreements --accept-source-agreements --silent --disable-interactivity
Write-Log "winget upgrade --all --accept-package-agreements --accept-source-agreements --silent --disable-interactivity"

Clear-UserCacheFiles
Clear-GlobalWindowsCache

# Clear console history
$ConsoleHistory = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $ConsoleHistory) {
    Remove-Item -Path $ConsoleHistory -Force
    Write-Log "Clear console history"
}

# Clear File Explorer Home history
$RecentFolder = "$env:APPDATA\Microsoft\Windows\Recent"
if (Test-Path -Path $RecentFolder) {
    Remove-Item -Path $RecentFolder -Recurse -Force -ErrorAction SilentlyContinue
	Write-Log "Clear File Explorer Home history"
}

$AutomaticDestinationsFolder = "$env:APPDATA\Microsoft\Windows\AutomaticDestinations"
if (Test-Path -Path $AutomaticDestinationsFolder) {
    Remove-Item -Path $AutomaticDestinationsFolder -Recurse -Force -ErrorAction SilentlyContinue
	Write-Log "removed $AutomaticDestinationsFolder -recurse"
}

$CustomDestinationsFolder = "$env:APPDATA\Microsoft\Windows\CustomDestinations"
if (Test-Path -Path $CustomDestinationsFolder) {
    Remove-Item -Path $CustomDestinationsFolder -Recurse -Force -ErrorAction SilentlyContinue
	Write-Log "removed $CustomDestinationsFolder -recurse"
}

function Remove-RegistryPathAndLog {
    param(
        [string]$RegistryPath
    )

    # Check if the registry key path exists
    if (Test-Path -Path $RegistryPath) {
        # Remove the registry key
        Remove-Item -Path $RegistryPath -Recurse -Force
        Write-Log ("Removed registry path $RegistryPath.")
    } else {
        Write-Host "Registry path $RegistryPath does not exist."
        Write-Log "Registry path $RegistryPath does not exist."
    }
}

# Clear typed history in File Explorer address bar
$registryPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths'
Remove-RegistryPathAndLog -RegistryPath $registryPath

# Clear typed history in Run dialog
$registryPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU'
Remove-RegistryPathAndLog -RegistryPath $registryPath

# Function to remove registry property and log command
function Remove-RegistryPropertyAndLog {
    param(
        [string]$RegistryPath,
        [string]$PropertyName
    )

    # Check if the registry key path exists
    if (Test-Path -Path $RegistryPath) {
        # Check if the property exists before attempting to remove it
        $propertyExists = Get-ItemProperty -Path $RegistryPath -Name $PropertyName -ErrorAction SilentlyContinue
        if ($propertyExists -ne $null) {
            Remove-ItemProperty -Path $RegistryPath -Name $PropertyName -Force
            Write-Log ("Removed property $PropertyName from registry path $RegistryPath.")
        } else {
            Write-Host "Property $PropertyName does not exist at path $RegistryPath."
            Write-Log "Property $PropertyName does not exist at path $RegistryPath."
        }
    }
    else {
        Write-Host "Registry path $RegistryPath does not exist."
        Write-Log "Registry path $RegistryPath does not exist."
    }
}

# Clear ArcHistory from Compression settings
$registryPath = 'HKCU:\Software\7-Zip\Compression'
$propertyName = 'ArcHistory'
Remove-RegistryPropertyAndLog -RegistryPath $registryPath -PropertyName $propertyName

# Clear PathHistory from Extraction settings
$registryPath = 'HKCU:\Software\7-Zip\Extraction'
$propertyName = 'PathHistory'
Remove-RegistryPropertyAndLog -RegistryPath $registryPath -PropertyName $propertyName

# Clear CopyHistory from FM settings
$registryPath = 'HKCU:\Software\7-Zip\FM'
$propertyName = 'CopyHistory'
Remove-RegistryPropertyAndLog -RegistryPath $registryPath -PropertyName $propertyName

# Clear FolderHistory from FM settings
$propertyName = 'FolderHistory'
Remove-RegistryPropertyAndLog -RegistryPath $registryPath -PropertyName $propertyName

# Clear PanelPath0 from FM settings
$propertyName = 'PanelPath0'
Remove-RegistryPropertyAndLog -RegistryPath $registryPath -PropertyName $propertyName

# Clear Notepad history
Remove-Item -Path "$env:localappdata\Packages\Microsoft.WindowsNotepad_8wekyb3d8bbwe\LocalState\TabState\*" -Force
Write-Log "Clear Notepad history"

# Clear Downloads, Pictures, Music, Videos folders
$DownloadsFolder = "$env:USERPROFILE\Downloads"
Get-ChildItem -Path $DownloadsFolder | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
Write-Log "Clear Downloads"

$PicturesFolder = "$env:USERPROFILE\Pictures"
Get-ChildItem -Path $PicturesFolder | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
Write-Log "Clear Pictures"

$MusicFolder = "$env:USERPROFILE\Music"
Get-ChildItem -Path $MusicFolder | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
Write-Log "Clear Music"

$VideosFolder = "$env:USERPROFILE\Videos"
Get-ChildItem -Path $VideosFolder -Recurse | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
Write-Log "Clear Videos"

$DocumentsFolder = "$env:USERPROFILE\Documents"
Get-ChildItem -Path $DocumentsFolder -Recurse | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
Write-Log "Clear Documents"

# Show Taskbar
$RegistryPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StuckRects3'
$RegistryProperty = "Settings"

# Get the current settings
$currentSettings = Get-ItemProperty -Path $RegistryPath

# Update the settings value (index 8) to 2
$currentSettings.$RegistryProperty[8] = 2

# Set the updated settings back to the registry
Set-ItemProperty -Path $RegistryPath -Name $RegistryProperty -Value $currentSettings.$RegistryProperty
Write-Log "Show Taskbar"

# Show Desktop Icons script
$RegistryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
$RegistryProperty = "HideIcons"

# Get the current settings
$currentSettings = Get-ItemProperty -Path $RegistryPath

# Update the HideIcons value to 0
$currentSettings.$RegistryProperty = 0

# Set the updated settings back to the registry
Set-ItemProperty -Path $RegistryPath -Name $RegistryProperty -Value $currentSettings.$RegistryProperty
Write-Log "Show Desktop Icons"

# Set wallpaper based on manufacturer
$Manufacturers = @(
    "c:\Windows\Web\Wallpaper\backgroundDefault.jpg",
    "c:\Windows\Web\Wallpaper\Dell\BlueLava_1112000xx_inspiron_wallpaper58095_16x9_72dpi_RGB.jpg",
    "c:\Windows\Web\Wallpaper\Dell\01.jpg",
    "c:\Windows\Web\Wallpaper\Dell\Win7 Blue 1920x1200.jpg",
    "c:\Windows\Web\Wallpaper\Dell\Win Blue 1920x1200.jpg",
    "c:\Windows\Web\Wallpaper\Dell\Wallpaper_Vostro_M13.jpg",
    "c:\Windows\Web\Wallpaper\Alienware\AW_ChromeHead_72dpi.jpg",
    "c:\Windows\Web\Wallpaper\dell\AFX_FHD.png",
    "c:\Windows\Web\Wallpaper\Hewlett-Packard Backgrounds\backgroundDefault.jpg",
    "c:\Windows\Web\Wallpaper\HP Backgrounds\backgroundDefault.jpg",
    "c:\Windows\System32\oobe\info\Wallpaper\backgroundDefault.jpg",
    "c:\Windows\Web\Wallpaper\Lenovo\LenovoWallpaper.jpg",
    "c:\Windows\Web\Wallpaper\Lenovo\Black Burst.jpg",
    "c:\Windows\Web\Wallpaper\Lenovo\3.jpg",
    "c:\Windows\ASUS\wallpapers\ASUS.jpg",
    "c:\Windows\Web\Wallpaper\acer01.jpg",
    "c:\Windows\Web\Wallpaper\WALLPAPER.jpg",
    "c:\Windows\Web\Wallpaper\img0.jpg",
    "c:\Windows\Web\Wallpaper\Surface\Surface.jpg",
    "c:\Windows\Web\Wallpaper\Windows\img0.jpg"
)

foreach ($manufacturer in $Manufacturers) {
    if (Test-Path $manufacturer) {
        Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name Wallpaper -Value $manufacturer -Force
        RUNDLL32.EXE user32.dll,UpdatePerUserSystemParameters
		Write-Log "successfully changed wallpaper with $manufacturer"
        break
    }
}

# Wait for user confirmation
Read-Host -Prompt "Press Enter to restart the computer..."