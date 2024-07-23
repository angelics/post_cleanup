Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$log = "C:\Windows\Logs\araid\araid_post.log"

# Get the directory of the original log file
$logDirectory = Split-Path -Path $log -Parent

# Function to log messages to the specified log file
function Write-Log {
    param(
        [string]$Message
    )
    Add-Content -Path $log -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message"
}

# Check if the original log file exists
if (Test-Path -Path $logDirectory) {
    # Delete the existing log file
	if (Test-Path -Path $log) {
    Remove-Item -Path $log -Force
	Write-Log "Deleted existing log file: $log"
	}
} else {
	New-Item -ItemType Directory -Path $logDirectory
	Write-Log "created $logDirectory"
}

Function Set-RegistryProperty {
    param(
        [Parameter(Mandatory = $true)][string]$registryPath,
        [Parameter(Mandatory = $true)][string]$propertyName,
        [Parameter(Mandatory = $true)][object]$value
    )

    # Check if the registry path exists, if not create it
    if (-not (Test-Path -Path $registryPath)) {
        New-Item -Path $registryPath -Force | Out-Null
    }

    # Check if the registry property exists, if not create it
    if (-not (Get-ItemProperty -Path $registryPath -Name $propertyName -ErrorAction SilentlyContinue)) {
        New-ItemProperty -Path $registryPath -Name $propertyName -Value $value -PropertyType DWord -Force | Out-Null
    } else {
        # Set the property value in the registry
        Set-ItemProperty -Path $registryPath -Name $propertyName -Value $value -Force
    }
}

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
    Remove-Dir "$env:APPDATA\Microsoft\Windows\Recent"
    Remove-Dir "$env:APPDATA\Microsoft\Windows\AutomaticDestinations"
    Remove-Dir "$env:APPDATA\Microsoft\Windows\CustomDestinations"
    Remove-Dir "C:\Intel"
    Remove-Dir "C:\AMD"
    Remove-Dir "C:\NVIDIA"
#1: Temporary Internet Files
#2: Cookies
#4: History
#8: Form Data
#16: Passwords
#32: Phishing Filter Data
#64: Web Page Recovery Data
#128: Download History
#256: Tracking Protection, ActiveX Filtering, and Do Not Track data
#512: Browser Session Restore
#1024: InPrivate Filtering Data
#2048: Cached feeds and WebSlices
#4096: Preferences
    C:\Windows\System32\rundll32.exe InetCpl.cpl, ClearMyTracksByProcess 8191

}

#------------------------------------------------------------------#
#- Clear-UserCacheFiles                                            #
#------------------------------------------------------------------#
Function Clear-UserCacheFiles
{
    Stop-BrowserSessions
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
        Clear-NotepadPP $localUser
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
    $browserNames = @("firefox.exe", "chrome.exe", "msedge.exe")
    ForEach ($browserName in $browserNames)
    {
        try
        {
            taskkill /f /im $browserName | Out-Null
			Write-Log "Successfully terminated $browserName"
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
#- Remove-File                                               #
#------------------------------------------------------------------#
Function Remove-File
{
    param([Parameter(Mandatory = $true)][string]$path)

    if ((Test-Path "$path"))
    {
        Remove-Item -Path "$path" -Force -ErrorAction SilentlyContinue
		Write-Log "file removed $path"
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
        $possibleCachePaths = @("Cache", "Cache2\entries\", "ChromeDWriteFontCache", "Code Cache", "GPUCache", "JumpListIcons", "JumpListIconsOld", "Media Cache", "Service Worker", "Top Sites", "VisitedLinks", "Web Data", "Preferences", "Local Storage", "Session Storage", "Cookies", "Network", "Sessions" , "IndexedDB")
        ForEach ($cachePath in $possibleCachePaths)
        {
            Remove-Dir "$path\$cachePath"
        }
		$possibleCacheFiles = @("History", "History-journal", "Shortcuts", "Shortcuts-journal", "DIPS", "DIPS-journal", "Network Action Predictor", "Network Action Predictor-journal")
		ForEach ($cacheFile in $possibleCacheFiles)
        {
            Remove-File "$path\$cacheFile"
        }
    }
}

#------------------------------------------------------------------#
#- Clear-MozillaTemplate                                           #
#------------------------------------------------------------------#
Function Clear-MozillaTemplate {
    param(
        [Parameter(Mandatory = $true)][string]$path,
		[Parameter(Mandatory = $true)][string]$name
    )

    if (Test-Path $path) {
        $profiles = Get-ChildItem $path | Where-Object { $_.Name -match "default" }
        foreach ($profile in $profiles) {
            Write-Host "Clearing cache for profile: $($profile.Name)"
            $AppDataPath = $profile.FullName
            $possibleCachePaths = @("cache", "cache2\entries", "cache2", "thumbnails", "webappsstore.sqlite", "chromeappstore.sqlite", "storage", "sessionstore-backups", "jumpListCache", "thumbnails")
            ForEach ($cachePath in $possibleCachePaths) {
                Remove-Dir "$AppDataPath\$cachePath"
            }
			$possibleCacheFiles = @("places.sqlite-wal", "places.sqlite", "places.sqlite-shm", "prefs.js")
            ForEach ($cacheFile in $possibleCacheFiles) {
                Remove-File "$AppDataPath\$cacheFile"
            }
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
    Remove-File "C:\users\$user\AppData\Local\Microsoft\Edge\User Data\Default\*.TMP"
    Remove-Dir "C:\users\$user\AppData\Local\Microsoft\Edge\User Data\Default\CacheStorage"
}

#------------------------------------------------------------------#
#- Clear-FirefoxCacheFiles                                         #
#------------------------------------------------------------------#
Function Clear-FirefoxCacheFiles
{
    param([string]$user = $env:USERNAME)
    Clear-MozillaTemplate "C:\users\$user\AppData\Local\Mozilla\Firefox\Profiles" "Browser Mozilla Firefox"
    Clear-MozillaTemplate "C:\users\$user\AppData\Roaming\Mozilla\Firefox\Profiles" "Browser Mozilla Firefox"
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

Function Clear-NotepadPP
{
    param([string]$user = $env:USERNAME)
    if ((Test-Path "C:\users\$user\AppData\Roaming\Notepad++"))
    {
		$possibleCachePaths = @("backup")
		ForEach ($cachePath in $possibleCachePaths) {
			Remove-Dir "$path\$cachePath"
		}
		$possibleCacheFiles = @("config.xml", "session.xml")
		ForEach ($cacheFile in $possibleCacheFiles) {
			Remove-File "$path\$cacheFile"
		}
    }
}

function Check-winget {
	
	# Check if winget is installed, win10 not installed by default
	# https://github.com/microsoft/winget-cli/issues/1861
	if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
		# Install winget
		IWR -Uri "https://github.com/microsoft/terminal/releases/download/v1.19.10302.0/Microsoft.WindowsTerminal_1.19.10302.0_8wekyb3d8bbwe.msixbundle_Windows10_PreinstallKit.zip" -OutFile ".\Windows10_PreinstallKit.zip"; Expand-Archive -Path ".\Windows10_PreinstallKit.zip" -DestinationPath ".\Windows10_PreinstallKit" -Force; Move-Item -Path ".\Windows10_PreinstallKit\Microsoft.UI.Xaml.2.8_8.2310.30001.0_x64__8wekyb3d8bbwe.appx" -Destination .; Remove-Item -Path ".\Windows10_PreinstallKit.zip" -Force; Remove-Item -Path ".\Windows10_PreinstallKit" -Recurse -Force
		Add-AppxPackage -Path ".\Microsoft.UI.Xaml.2.8_8.2310.30001.0_x64__8wekyb3d8bbwe.appx"
		Remove-File ".\Microsoft.UI.Xaml.2.8_8.2310.30001.0_x64__8wekyb3d8bbwe.appx"
		Add-AppxPackage -Path https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx
		Add-AppxPackage -Path "https://aka.ms/getwinget"
	}
	
	Write-Output "y" | winget upgrade
}

Function Araid-install-package {
	
	Check-winget

    try {
        $response = Invoke-WebRequest -Uri https://raw.githubusercontent.com/angelics/post_cleanup/main/packages.json -UseBasicParsing
        $FilePath = "$env:systemroot\Logs\packages.json"
        $response.Content | Set-Content -Path $FilePath -Force
        Write-Log "Downloaded and saved packages.json to $FilePath"
    } catch {
        Write-Log "Failed to download packages.json: $_"
        return
    }

	Write-Log "Start winget install, with default softwares using: $FilePath"
	Start-Process cmd.exe -ArgumentList "/c winget import -i $FilePath --ignore-unavailable --ignore-versions --accept-package-agreements --accept-source-agreements --disable-interactivity --no-upgrade" -Wait
	
    Remove-Item -Path $FilePath -Force
}

function Araid-upgrade-package {
	
	Check-winget
	
    $commands = @(
        "winget pin add --id Discord.Discord --blocking",
        "winget pin add --id Microsoft.DevHome --blocking",
        "winget pin add --id Cisco.Webex --blocking",
		"winget upgrade --all --accept-package-agreements --accept-source-agreements --silent --disable-interactivity"
        
    )
    
    $commandString = $commands -join " && "
    
	Write-Log "Blocking upgrade for Discord.Discord"
	Write-Log "Blocking upgrade for Microsoft.DevHome"
	Write-Log "Blocking upgrade for Cisco.Webex"
	Write-Log "Start winget upgrade softwares."
    Start-Process cmd.exe -ArgumentList "/c $commandString" -Wait
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

Function Araid-CleanAndRestart {
	# Show Taskbar
	$registryPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StuckRects3'
	$propertyName = 'Settings'

	# Get the current settings
	$currentSettings = Get-ItemProperty -Path $RegistryPath

	# Update the settings value (index 8) to 2
	$currentSettings.Settings[8] = 2

	Set-RegistryProperty -registryPath $registryPath -propertyName $propertyName -value $currentSettings.Settings
	Write-Log "Show Taskbar"

	# Show Desktop Icons
	$registryPath = "HKCU:\SOFTWARE\Microsoft\Windows\Shell\Bags\1\Desktop"
	$propertyName = 'FFlags'
	$value = 1075839524
	#1075839520 (Auto arrange icons = OFF and Align icons to grid = OFF) 
	#1075839521 (Auto arrange icons = ON and Align icons to grid = OFF) 
	#1075839524 (Auto arrange icons = OFF and Align icons to grid = ON) default
	#1075839525 (Auto arrange icons = ON and Align icons to grid = ON)
	Set-RegistryProperty -registryPath $registryPath -propertyName $propertyName -value $value

	$registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
	$propertyName = 'HideIcons'
	$value = 0
	Set-RegistryProperty -registryPath $registryPath -propertyName $propertyName -value $value
	Write-Log "Show Desktop Icons"

	$registryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer'
	$propertyName = 'ShowRecent'
	$value = 0
	Set-RegistryProperty -registryPath $registryPath -propertyName $propertyName -value $value
	Write-Log "Remove Recent in File Explorer Home"

	$registryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer'
	$propertyName = 'ShowFrequent'
	$value = 0
	Set-RegistryProperty -registryPath $registryPath -propertyName $propertyName -value $value
	Write-Log "Remove Frequent Folders in Quick Access in File Explorer Home"

	$registryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer'
	$propertyName = 'ShowCloudFilesInQuickAccess'
	$value = 0
	Set-RegistryProperty -registryPath $registryPath -propertyName $propertyName -value $value
	Write-Log "Turn Off Show Files from Office.com in File Explorer Home for Current User"

	#$registryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
	#$propertyName = 'DisableGraphRecentItems'
	#$value = 1
	#Set-RegistryProperty -registryPath $registryPath -propertyName $propertyName -value $value
	#Write-Log "Disable Show Files from Office.com in File Explorer Home for All Users"

	$registryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	$propertyName = 'LaunchTo'
	$value = 1
	Set-RegistryProperty -registryPath $registryPath -propertyName $propertyName -value $value
	Write-Log "Open File Explorer to This PC"

	$registryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	$propertyName = 'Hidden'
	$value = 1
	Set-RegistryProperty -registryPath $registryPath -propertyName $propertyName -value $value
	Write-Log "Show hidden files, folders and drives"
	
	Clear-UserCacheFiles
	Clear-GlobalWindowsCache

	# Clear console history
	$ConsoleHistory = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
	Write-Log "Clear console history"
	Remove-File "$ConsoleHistory"
	
	# Clear typed history in File Explorer address bar
	$registryPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths'
	Write-Log "Clear typed history in File Explorer address bar"
	Remove-RegistryPathAndLog -RegistryPath $registryPath

	# Clear typed history in Run dialog
	$registryPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU'
	Write-Log "Clear typed history in Run dialog"
	Remove-RegistryPathAndLog -RegistryPath $registryPath
	
	# Clear Media Player Classic
	$registryPath = 'HKCU:\SOFTWARE\MPC-HC\MPC-HC\MediaHistory'
	Write-Log "Clear Media Player Classic"
	Remove-RegistryPathAndLog -RegistryPath $registryPath
	
	# Clear ArcHistory from Compression settings
	$registryPath = 'HKCU:\Software\7-Zip\Compression'
	$propertyName = 'ArcHistory'
	Write-Log "Clear 7zip ArcHistory from Compression settings"
	Remove-RegistryPropertyAndLog -RegistryPath $registryPath -PropertyName $propertyName

	# Clear PathHistory from Extraction settings
	$registryPath = 'HKCU:\Software\7-Zip\Extraction'
	$propertyName = 'PathHistory'
	Write-Log "Clear 7zip PathHistory from Extraction settings"
	Remove-RegistryPropertyAndLog -RegistryPath $registryPath -PropertyName $propertyName

	# Clear CopyHistory from FM settings
	$registryPath = 'HKCU:\Software\7-Zip\FM'
	$propertyName = 'CopyHistory'
	Write-Log "Clear 7zip CopyHistory from FM settings"
	Remove-RegistryPropertyAndLog -RegistryPath $registryPath -PropertyName $propertyName

	# Clear FolderHistory from FM settings
	$propertyName = 'FolderHistory'
	Write-Log "Clear 7zip FolderHistory from FM settings"
	Remove-RegistryPropertyAndLog -RegistryPath $registryPath -PropertyName $propertyName

	# Clear PanelPath0 from FM settings
	$propertyName = 'PanelPath0'
	Write-Log "Clear 7zip PanelPath0 from FM settings"
	Remove-RegistryPropertyAndLog -RegistryPath $registryPath -PropertyName $propertyName

	# Clear Notepad history
	Remove-Item -Path "$env:localappdata\Packages\Microsoft.WindowsNotepad_*\LocalState\TabState\*" -Recurse -Force -ErrorAction SilentlyContinue
	Write-Log "Clear Notepad history"

	# Clear Microsoft Edge cache
	Remove-Item -Path "$env:LOCALAPPDATA\Packages\Microsoft.MicrosoftEdge_*\AC\#!001\MicrosoftEdge\Cache\*" -Recurse -Force -ErrorAction SilentlyContinue
	Write-Log "Clear Microsoft Edge cache"

	# Clear Downloads, Pictures, Music, Videos folders
	$DownloadsFolder = "$env:USERPROFILE\Downloads"
	Remove-Dir "$DownloadsFolder"

	$PicturesFolder = "$env:USERPROFILE\Pictures"
	Remove-Dir "$PicturesFolder"

	$MusicFolder = "$env:USERPROFILE\Music"
	Remove-Dir "$MusicFolder"

	$VideosFolder = "$env:USERPROFILE\Videos"
	Remove-Dir "$VideosFolder"

	$DocumentsFolder = "$env:USERPROFILE\Documents"
	Remove-Dir "$DocumentsFolder"

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

	#List all hidden devices
	$unknown_devs = Get-PnpDevice | Where-Object{$_.Status -eq 'Unknown'} 

	#loop through all hidden devices to remove them using pnputil
	ForEach($dev in $unknown_devs){
		# Construct the command arguments
		$arguments = "/remove-device $($dev.InstanceId)"
		
		Start-Process -FilePath "pnputil.exe" -ArgumentList $arguments -Wait
		
		Write-Log "$($dev.InstanceId) has been removed"
	}

	# Wait for user confirmation
	Read-Host -Prompt "Press Enter to restart the computer..."
}

taskkill /f /im explorer.exe
Write-Log "Task killed: explorer.exe"

# Check if the Win32 type already exists
if (-not ([System.Management.Automation.PSTypeName]'Win32').Type) {
    Add-Type @"
    using System;
    using System.Runtime.InteropServices;

    public class Win32 {
        [DllImport("user32.dll")]
        public static extern int SetWindowLong(IntPtr hWnd, int nIndex, int dwNewLong);
        [DllImport("user32.dll")]
        public static extern int GetWindowLong(IntPtr hWnd, int nIndex);
        [DllImport("user32.dll")]
        public static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int X, int Y, int cx, int cy, uint uFlags);

        public const int GWL_STYLE = -16;
        public const int WS_MINIMIZEBOX = 0x00020000;
        public const int WS_MAXIMIZEBOX = 0x00010000;
        public const int WS_SYSMENU = 0x00080000;
        public const uint SWP_NOSIZE = 0x0001;
        public const uint SWP_NOMOVE = 0x0002;
        public const uint SWP_NOZORDER = 0x0004;
        public const uint SWP_FRAMECHANGED = 0x0020;
        public static readonly IntPtr HWND_TOPMOST = new IntPtr(-1);
        public static readonly IntPtr HWND_TOP = IntPtr.Zero;
    }
"@
}

# Create the form
$form = New-Object System.Windows.Forms.Form
$form.Text = "Araid Scripts"
$form.Size = New-Object System.Drawing.Size(480, 250)
$form.TopMost = $true

# Remove minimize, maximize, and close buttons
$form.Add_Shown({
    $hWnd = $form.Handle
    $currentStyle = [Win32]::GetWindowLong($hWnd, [Win32]::GWL_STYLE)
    $newStyle = $currentStyle -band -bnot ([Win32]::WS_SYSMENU)
    [Win32]::SetWindowLong($hWnd, [Win32]::GWL_STYLE, $newStyle)
    [Win32]::SetWindowPos($hWnd, [Win32]::HWND_TOP, 0, 0, 0, 0, [Win32]::SWP_NOSIZE -bor [Win32]::SWP_NOMOVE -bor [Win32]::SWP_NOZORDER -bor [Win32]::SWP_FRAMECHANGED)
})

$allowClose = $false

# Prevent the form from being closed
$form.Add_FormClosing({
    if (-not $allowClose) {
        $_.Cancel = $true
    }
})

# Create label for install
$label1 = New-Object System.Windows.Forms.Label
$label1.Text = "Install default softwares"
$label1.Location = New-Object System.Drawing.Point(270, 40)
$label1.Size = New-Object System.Drawing.Size(190, 20)

# Create button for install
$button1 = New-Object System.Windows.Forms.Button
$button1.Text = "1. Install Package"
$button1.Location = New-Object System.Drawing.Point(50, 30)
$button1.Size = New-Object System.Drawing.Size(190, 30)
$button1.Add_Click({
	Araid-install-package
})

# Create label for Upgrade
$label2 = New-Object System.Windows.Forms.Label
$label2.Text = "Upgrade all installed softwares"
$label2.Location = New-Object System.Drawing.Point(270, 100)
$label2.Size = New-Object System.Drawing.Size(190, 20)

# Create button for Upgrade
$button2 = New-Object System.Windows.Forms.Button
$button2.Text = "2. Upgrade Package"
$button2.Location = New-Object System.Drawing.Point(50, 90)
$button2.Size = New-Object System.Drawing.Size(190, 30)
$button2.Add_Click({
    Araid-upgrade-package
})

# Create label for Clean and Restart
$label3 = New-Object System.Windows.Forms.Label
$label3.Text = "Full OS drive clean and reboot"
$label3.Location = New-Object System.Drawing.Point(270, 160)
$label3.Size = New-Object System.Drawing.Size(190, 20)

# Create button for Clean and Restart
$button3 = New-Object System.Windows.Forms.Button
$button3.Text = "3. Clean and Restart"
$button3.Location = New-Object System.Drawing.Point(50, 150)
$button3.Size = New-Object System.Drawing.Size(190, 30)
$button3.Add_Click({
	$allowClose = $true
	$form.Close()
    Araid-CleanAndRestart
})

# Add buttons to the form
$form.Controls.Add($label1)
$form.Controls.Add($button1)
$form.Controls.Add($label2)
$form.Controls.Add($button2)
$form.Controls.Add($label3)
$form.Controls.Add($button3)

# Show the form
$form.ShowDialog()