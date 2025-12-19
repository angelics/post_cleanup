Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$global:wingetChecked = $false

$log = "$env:systemroot\araid\araid_post.log"

# Get the directory of the original log file
$logDirectory = Split-Path -Path $log -Parent

# Function to log messages to the specified log file
Function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [string]$Color = "White"
    )

    try {
        # Timestamp for log entry
        $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

        # Write to log file
        Add-Content -Path $log -Value "[$timestamp] $Message"

        # Also show live output
        Write-Host $Message -ForegroundColor $Color
    }
    catch {
        Write-Host "Failed to write log: $_" -ForegroundColor Red
    }
}

$ErrorActionPreference = "Stop"
trap {
    Write-Log "Fatal error: $_" "Red"
    exit 1
}

# Ensure log directory exists
if (!(Test-Path $logDirectory)) {
    New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
}

# Reset log file once
Remove-Item -Path $log -Force -ErrorAction SilentlyContinue

Write-Log "System Information:"
systeminfo | ForEach-Object {
    Add-Content -Path $log -Value "    $_"
}

Function Set-RegistryProperty {
    param(
        [Parameter(Mandatory)][string]$registryPath,
        [Parameter(Mandatory)][string]$propertyName,
        [Parameter(Mandatory)][object]$value
    )

    if (-not (Test-Path $registryPath)) {
        New-Item -Path $registryPath -Force | Out-Null
    }

    Set-ItemProperty -Path $registryPath -Name $propertyName -Value $value -Force
    Write-Log "Set $propertyName in $registryPath"
}


# https://gist.githubusercontent.com/mark05e/745afaf5604487b804ede2cdc38a977f/raw/95f5a609972cff862ce3d92ac4c2b918d37de1c1/DriveClean.ps1
# https://github.com/inode64/WindowsClearCache
#------------------------------------------------------------------#
#- Clear-GlobalWindowsCache                                        #
#------------------------------------------------------------------#
Function Clear-GlobalWindowsCache
{
	#$env:WINDIR = C:\Windows
	#$env:systemroot = C:\Windows
	#$env:homedrive = C:\
	#$env:ProgramData = C:\ProgramData
    Remove-SubFile "$env:systemroot\Temp"
    Remove-SubFile "$env:systemroot\CbsTemp"
    Remove-SubFile "$env:systemroot\SystemTemp"
    Remove-SubFile "$env:systemroot\Minidump"
    Remove-SubFile "$env:homedrive\Temp"
    Remove-SubFile "$env:homedrive\tmp"
    Remove-SubFile "$env:systemroot\Prefetch"
    Remove-SubFile "$env:systemroot\ServiceProfiles\NetworkService\Appdata\Local\Microsoft\DeliveryOptimization\Logs\*.etl"
    Remove-File "$env:homedrive\Intel"
    Remove-File "$env:homedrive\AMD"
    Remove-File "$env:homedrive\NVIDIA"
	Remove-SubFile "$env:ProgramData\USOShared\Logs" # Delivery Optimization Files
	Remove-SubFile "$env:ProgramData\Microsoft\Windows\WER\Temp" # Delivery Optimization Files
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
    Start-Process -FilePath "$env:systemroot\System32\rundll32.exe" -ArgumentList "InetCpl.cpl, ClearMyTracksByProcess 8191" -Wait -NoNewWindow

}

Function Clear-UserCacheFiles
{
    ForEach ($localUser in Get-ChildItem "C:\Users" -Directory |
         Where-Object { $_.Name -notin @("Public","Default","Default User","All Users") } |
         Select-Object -ExpandProperty Name)

    {
		Clear-AcrobatCacheFiles $localUser
        Clear-ChromeCacheFiles $localUser
        Clear-DiscordCacheFiles $localUser
        Clear-EdgeCacheFiles $localUser
        Clear-FirefoxCacheFiles $localUser
        Clear-MicrosoftOfficeCacheFiles $localUser
        Clear-SteamCacheFiles $localUser
        Clear-TeamsCacheFiles $localUser
        Clear-NotepadPP $localUser
    }
	
	Clear-WindowsUserCacheFiles
	Clear-MicrosoftDefenderAntivirus
	Clear-WindowsUpdateCache
	Clear-WindowsSearch
	
}

#------------------------------------------------------------------#
#- Clear-WindowsUserCacheFiles                                     #
#------------------------------------------------------------------#
Function Clear-WindowsUserCacheFiles {
	
	#$env:appdata = C:\Users\LocalAdmin\AppData\Roaming
	#$env:LOCALAPPDATA = C:\Users\LocalAdmin\AppData\Local
	#$env:USERPROFILE = C:\Users\LocalAdmin
    Remove-SubFile "$env:LOCALAPPDATA\Microsoft\Internet Explorer\Cache"
    Remove-SubFile "$env:LOCALAPPDATA\Microsoft\Internet Explorer\Recovery"
    Remove-SubFile "$env:LOCALAPPDATA\Microsoft\Internet Explorer\Tiles"
    Remove-SubFile "$env:LOCALAPPDATA\Microsoft\Terminal Server Client\Cache"
    Remove-SubFile "$env:LOCALAPPDATA\Microsoft\Windows\Caches"
    Remove-SubFile "$env:LOCALAPPDATA\Microsoft\Windows\History\low"
    Remove-SubFile "$env:LOCALAPPDATA\Microsoft\Windows\IECompatCache"
    Remove-SubFile "$env:LOCALAPPDATA\Microsoft\Windows\IECompatUaCache"
    Remove-SubFile "$env:LOCALAPPDATA\Microsoft\Windows\IEDownloadHistory"
    Remove-SubFile "$env:LOCALAPPDATA\Microsoft\Windows\INetCache"
    Remove-SubFile "$env:LOCALAPPDATA\Packages\MicrosoftWindows.Client.WebExperience_*\AC\INetCache"
    Remove-SubFile "$env:LOCALAPPDATA\Packages\Microsoft.DesktopAppInstaller_*\AC\INetCache"
    Remove-SubFile "$env:LOCALAPPDATA\Packages\MicrosoftWindows.Client.CBS_*\AC\INetCache"
    Remove-SubFile "$env:LOCALAPPDATA\Packages\Microsoft.Windows.StartMenuExperienceHost_*\AC\INetCache"
	Remove-SubFile "$env:LOCALAPPDATA\Microsoft\Windows\INetCookies"
    Remove-SubFile "$env:LOCALAPPDATA\Microsoft\Windows\Temporary Internet Files"
    Remove-SubFile "$env:LOCALAPPDATA\Microsoft\Windows\WebCache"
    Remove-SubFile "$env:LOCALAPPDATA\Microsoft\Windows\WER"
    Remove-SubFile "$env:LOCALAPPDATA\Temp"
	Remove-SubFile "$env:LOCALAPPDATA\CrashDumps"
	Remove-SubFile "$env:LOCALAPPDATA\D3DSCache" # DirectX Shader Cache
	Remove-SubFile "$env:LOCALAPPDATA\Microsoft\Windows\Explorer" # Thumbnails
	Remove-SubFile "$env:LOCALAPPDATA\Packages\Microsoft.WindowsNotepad_*\LocalState\TabState" # Clear Notepad history
	Remove-SubFile "$env:LOCALAPPDATA\Packages\Microsoft.MicrosoftEdge_*\AC\#!001\MicrosoftEdge\Cache\" # Clear Microsoft Edge cache
	Remove-SubFile "$env:APPDATA\Microsoft\Windows\Recent"
    Remove-SubFile "$env:APPDATA\Microsoft\Windows\AutomaticDestinations"
    Remove-SubFile "$env:APPDATA\Microsoft\Windows\CustomDestinations"
	Remove-SubFile "$env:USERPROFILE\Downloads"
	Remove-SubFile "$env:USERPROFILE\Pictures"
	Remove-SubFile "$env:USERPROFILE\Music"
	Remove-SubFile "$env:USERPROFILE\Videos"
	Remove-SubFile "$env:USERPROFILE\Documents"
	
}

Function Clear-MicrosoftDefenderAntivirus
{
	#$env:ProgramData = C:\ProgramData
    Remove-SubFile "$env:ProgramData\Microsoft\Windows Defender\Scans\History\CacheManager"
    Remove-SubFile "$env:ProgramData\Microsoft\Windows Defender\Scans\History\Results\Quick"
    Remove-SubFile "$env:ProgramData\Microsoft\Windows Defender\Scans\History\Results\Resource"
    Remove-SubFile "$env:ProgramData\Microsoft\Windows Defender\Scans\History\Service"
    Remove-SubFile "$env:ProgramData\Microsoft\Windows Defender\Scans\History\Store"
    Remove-SubFile "$env:ProgramData\Microsoft\Windows Defender\Scans\History\Results\System"
    Remove-SubFile "$env:ProgramData\Microsoft\Windows Defender\Scans\mpenginedb.db"
    Remove-SubFile "$env:ProgramData\Microsoft\Windows Defender\Support"
	Remove-SubFile "$env:ProgramData\Microsoft\Windows Defender\Definition Updates\{GUID}"
    Remove-File "$env:ProgramData\Microsoft\Windows Defender\Scans\mpcache-*.bin"
    Remove-File "$env:ProgramData\Microsoft\Windows Defender\Scans\mpcache-*.log"
}

function Stop-Services {
    param (
        [Parameter(Mandatory)]
        [string]$Service,

        [int]$RetryCount = 3,
        [int]$RetryDelaySeconds = 5
    )

    for ($attempt = 1; $attempt -le $RetryCount; $attempt++) {
        try {
            $svc = Get-Service -Name $Service -ErrorAction Stop

            if ($svc.Status -eq 'Stopped') {
                Write-Log "$Service is already stopped."
                return
            }

            Write-Log "Requesting stop for $Service (attempt $attempt)"
            Stop-Service -Name $Service -ErrorAction Stop

            Start-Sleep -Seconds $RetryDelaySeconds

        } catch {
            Write-Log "Stop attempt $attempt failed for ${Service}: $_" "Yellow"
        }
    }
}


function Clear-WindowsUpdateCache {
	$services = @(
        "wuauserv",           # Windows Update
        "bits",               # Background Intelligent Transfer Service
        "dosvc",              # Delivery Optimization
        "cryptsvc"            # Cryptographic Services
    )
	
	foreach ($svc in $services) {
		Stop-ServiceSafely -ServiceName $svc -TimeoutSeconds 120
	}
	
	Remove-SubFile "$env:systemroot\SoftwareDistribution\Download"
	Write-Log "Windows Update cache files deleted."
	
}

function Clear-WindowsSearch {
	
	#$env:WINDIR = C:\Windows
	
	Stop-ServiceSafely -ServiceName "WSearch" -TimeoutSeconds 120
	
	# Delete Windows Search cache files
	Remove-SubFile "$env:LOCALAPPDATA\Packages\Microsoft.Windows.Client.CBS_*\LocalState\Search"
	Write-Log "Deleted Windows Search cache files"
	
}

Function Remove-SubFile {
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        Write-Log "Path not found (skipped): $Path" "DarkGray"
        return
    }

    try {
		Get-ChildItem -Path $Path -Force -ErrorAction SilentlyContinue |
			Where-Object { -not $_.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint) } |
			Remove-Item -Force -Recurse -ErrorAction SilentlyContinue

        Write-Log "Deleted contents of: $Path"
    }
    catch {
        Write-Log "Failed to delete contents of: $Path. Error: $_" "Yellow"
    }
}

Function Remove-File {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (Test-Path -Path $Path) {
        try {
            Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue
            Write-Log "Removed: $Path"
        }
        catch {
            Write-Log "Failed to remove: $Path. Error: $_" "Yellow"
        }
    }
    else {
        Write-Log "File not found (skipped): $Path" "DarkGray"
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
        Write-Log "Clear cache $name"
        $possibleCachePaths = @("Cache", "Cache2\entries\", "ChromeDWriteFontCache", "Code Cache", "GPUCache", "JumpListIcons", "JumpListIconsOld", "Media Cache", "Service Worker", "Top Sites", "VisitedLinks", "Web Data", "Preferences", "Local Storage", "Session Storage", "Cookies", "Network", "Sessions" , "IndexedDB")
        ForEach ($cachePath in $possibleCachePaths)
        {
            Remove-SubFile "$path\$cachePath"
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
            $AppDataPath = $profile.FullName
            $possibleCachePaths = @("cache", "cache2\entries", "cache2", "thumbnails", "webappsstore.sqlite", "chromeappstore.sqlite", "storage", "sessionstore-backups", "jumpListCache", "thumbnails")
            ForEach ($cachePath in $possibleCachePaths) {
                Remove-SubFile "$AppDataPath\$cachePath"
            }
			$possibleCacheFiles = @("places.sqlite-wal", "places.sqlite", "places.sqlite-shm", "prefs.js","SiteSecurityServiceState.txt", "formhistory.sqlite", "formhistory.sqlite-journal", "favicons.sqlite-wal", "cookies.sqlite")
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
    Remove-SubFile "C:\users\$user\AppData\Local\Google\Chrome\User Data\SwReporter\"
}

#------------------------------------------------------------------#
#- Clear-EdgeCache                                                 #
#------------------------------------------------------------------#
Function Clear-EdgeCacheFiles
{
    param([string]$user = $env:USERNAME)
    Clear-ChromeTemplate "C:\users\$user\AppData\Local\Microsoft\Edge\User Data\Default" "Browser Microsoft Edge"
    Remove-File "C:\users\$user\AppData\Local\Microsoft\Edge\User Data\Default\*.TMP"
    Remove-SubFile "C:\users\$user\AppData\Local\Microsoft\Edge\User Data\Default\CacheStorage"
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
                Remove-SubFile "$DirName\$AcrobatAppDataPath\$cachePath"
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
            Remove-SubFile "$teamsAppDataPath\$cachePath"
        }
    }
	
	Remove-SubFile "C:\users\$user\AppData\Local\Packages\MSTeams_*\LocalCache\Microsoft\MSTeams"
		
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
                remove-item -force -recurse -ErrorAction SilentlyContinue -ErrorAction SilentlyContinue
        Get-ChildItem "C:\users\$user\AppData\Local\Microsoft\Outlook\*.ost" -Recurse -Force -ErrorAction SilentlyContinue |
                remove-item -force -recurse -ErrorAction SilentlyContinue -ErrorAction SilentlyContinue
        Get-ChildItem "C:\users\$user\AppData\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook\*" -Recurse -Force -ErrorAction SilentlyContinue |
                remove-item -force -recurse -ErrorAction SilentlyContinue -ErrorAction SilentlyContinue
        Get-ChildItem "C:\users\$user\AppData\Local\Microsoft\Windows\Temporary Internet Files\Content.MSO\*" -Recurse -Force -ErrorAction SilentlyContinue |
                remove-item -force -recurse -ErrorAction SilentlyContinue -ErrorAction SilentlyContinue
        Get-ChildItem "C:\users\$user\AppData\Local\Microsoft\Windows\Temporary Internet Files\Content.Word\*" -Recurse -Force -ErrorAction SilentlyContinue |
                remove-item -force -recurse -ErrorAction SilentlyContinue -ErrorAction SilentlyContinue
    }
}

Function Clear-NotepadPP {
    param(
        [string]$User = $env:USERNAME
    )

    $path = "C:\Users\$User\AppData\Roaming\Notepad++"

    if (Test-Path -Path $path) {

        Write-Log "Clearing Notepad++ cache for user: $User"

        $possibleCachePaths = @("backup")
        foreach ($cachePath in $possibleCachePaths) {
            Remove-SubFile (Join-Path $path $cachePath)
        }

        $possibleCacheFiles = @("config.xml", "session.xml")
        foreach ($cacheFile in $possibleCacheFiles) {
            Remove-File (Join-Path $path $cacheFile)
        }

        Write-Log "Notepad++ cleanup completed for user: $User"
    }
    else {
        Write-Log "Notepad++ not found for user: $User (skipped)" "DarkGray"
    }
}


function Clear-DuplicateOldDrivers {
	
	#https://github.com/maxbakhub/winposh/blob/main/WindowsDesktopManagement/RemoveOldDuplicateDrivers.ps1
	$dismOut = dism /online /get-drivers
	$Lines = $dismOut | select -Skip 10
	$Operation = "theName"
	$Drivers = @()
	foreach ( $Line in $Lines ) {
		$tmp = $Line
		$txt = $($tmp.Split( ':' ))[1]
		switch ($Operation) {
			'theName' { $Name = $txt
						 $Operation = 'theFileName'
						 break
					   }
			'theFileName' { $FileName = $txt.Trim()
							 $Operation = 'theEntr'
							 break
						   }
			'theEntr' { $Entr = $txt.Trim()
						 $Operation = 'theClassName'
						 break
					   }
			'theClassName' { $ClassName = $txt.Trim()
							  $Operation = 'theVendor'
							  break
							}
			'theVendor' { $Vendor = $txt.Trim()
						   $Operation = 'theDate'
						   break
						 }
			'theDate' { # we'll change the default date format for easy sorting
						 $tmp = $txt.split( '.' )
						 $txt = "$($tmp[2]).$($tmp[1]).$($tmp[0].Trim())"
						 $Date = $txt
						 $Operation = 'theVersion'
						 break
					   }
			'theVersion' { $Version = $txt.Trim()
							$Operation = 'theNull'
							$params = [ordered]@{ 'FileName' = $FileName
												  'Vendor' = $Vendor
												  'Date' = $Date
												  'Name' = $Name
												  'ClassName' = $ClassName
												  'Version' = $Version
												  'Entr' = $Entr
												}
							$obj = New-Object -TypeName PSObject -Property $params
							$Drivers += $obj
							break
						  }
			 'theNull' { $Operation = 'theName'
						  break
						 }
		}
	}
	$last = ''
	$NotUnique = @()
	foreach ( $Dr in $($Drivers | sort Filename) ) {
		if ($Dr.FileName -eq $last  ) {  $NotUnique += $Dr  }
		$last = $Dr.FileName
	}
	$NotUnique | sort FileName | ft
	# search for duplicate drivers 
	$list = $NotUnique | select -ExpandProperty FileName -Unique
	$ToDel = @()
	foreach ( $Dr in $list ) {
		# Write-Host "duplicate driver found" -ForegroundColor Yellow
		$sel = $Drivers | where { $_.FileName -eq $Dr } | sort date -Descending | select -Skip 1
		$sel | ft
		$ToDel += $sel
	}
	# Write-Host "List of driver version  to remove" -ForegroundColor Red
	$ToDel | ft
	# Removing old driver versions
	# Uncomment the Invoke-Expression to automatically remove old versions of device drivers
	if ($ToDel) {
		foreach ($item in $ToDel) {
			$Name = $($item.Name).Trim()
			$FileName = $($item.FileName).Trim()
			$Vendor = $($item.Vendor).Trim()
			$Date = $($item.Date).Trim()
			$ClassName = $($item.ClassName).Trim()
			$Version = $($item.Version).Trim()
			$Entr = $($item.Entr).Trim()
			
			# Write-Host "deleting $Name" -ForegroundColor Yellow
			
			try {
				Start-Process pnputil.exe -ArgumentList "/delete-driver $Name /force" -Wait
				Write-Log "Successfully removed driver: Name=$Name, FileName=$FileName, Vendor=$Vendor, Date=$Date, ClassName=$ClassName, Version=$Version, Entr=$Entr"
			} catch {
				Write-Log "Failed to remove driver: Name=$Name, FileName=$FileName, Vendor=$Vendor, Date=$Date, ClassName=$ClassName, Version=$Version, Entr={$Entr}. Error: $_"
			}
		}
	} else {
        Write-Log "No old or duplicate drivers to remove."
    }

}

function Get-WingetVersion {
	
    try {
        # Run winget --version and remove any leading/trailing whitespace and the "v" prefix
        $wingetVersionString = (winget --version) -replace '^v', '' -replace '\s+', ''
        
        # Convert to [version] type
        return [version]$wingetVersionString
    } catch {
        Write-Error "Failed to parse winget version. $_"
        return [version]"0.0" # Return a default value if there's an error
    }
	
}

function Check-Winget {

    if ($global:wingetChecked) {
        return
    }

    Write-Log "Checking winget installation"

    $wingetCmd = Get-Command winget -ErrorAction SilentlyContinue
    if ($wingetCmd) {
        $wingetVersion = Get-WingetVersion
        Write-Log "Winget detected. Version: $wingetVersion"
    } else {
        $wingetVersion = [version]"0.0"
        Write-Log "Winget not found"
    }

    $minVersion = [version]"1.6"

    if ($wingetVersion -lt $minVersion) {

        Write-Log "Winget upgrade/install required (minimum $minVersion)" "Yellow"

        $temp = Join-Path $env:TEMP "winget"
        New-Item -ItemType Directory -Path $temp -Force | Out-Null

        try {
            Write-Log "Downloading Windows Terminal PreinstallKit"
            Invoke-WebRequest `
                -Uri "https://github.com/microsoft/terminal/releases/download/v1.19.10302.0/Microsoft.WindowsTerminal_1.19.10302.0_8wekyb3d8bbwe.msixbundle_Windows10_PreinstallKit.zip" `
                -OutFile "$temp\PreinstallKit.zip"

            Expand-Archive "$temp\PreinstallKit.zip" "$temp\PreinstallKit" -Force

            $uiXaml = "$temp\Microsoft.UI.Xaml.appx"
            Move-Item `
                "$temp\PreinstallKit\Microsoft.UI.Xaml.2.8_8.2310.30001.0_x64__8wekyb3d8bbwe.appx" `
                $uiXaml -Force

            Write-Log "Installing Microsoft.UI.Xaml"
            Add-AppxPackage -Path $uiXaml -ForceApplicationShutdown

            Write-Log "Installing Microsoft.VCLibs"
            Add-AppxPackage -Path "https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx" -ForceApplicationShutdown

            Write-Log "Installing winget"
            Add-AppxPackage -Path "https://aka.ms/getwinget" -ForceApplicationShutdown

        } catch {
            Write-Log "Winget installation failed: $_" "Red"
            return
        } finally {
            Remove-Item $temp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    # Enable winget setting only if winget exists
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-Log "Configuring winget settings"
        winget settings --enable BypassCertificatePinningForMicrosoftStore 2>$null
    } else {
        Write-Log "Winget not available after install attempt" "Yellow"
    }

    $global:wingetChecked = $true
}

Function Araid-install-package {
	
	Clear-Host
	
	Write-Log "install started."
	Write-Host "Please wait..."
	
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
	Start-Process cmd.exe -ArgumentList "/c winget import -i $FilePath --ignore-unavailable --ignore-versions --accept-package-agreements --accept-source-agreements --disable-interactivity --no-upgrade" -Wait -NoNewWindow
    # Check if WhatsApp is installed
    $whatsapp = winget list --id "9NKSQGP7F2NH" --exact --accept-source-agreements | Out-String
    if ($whatsapp -match "9NKSQGP7F2NH") {
        Write-Log "WhatsApp is already installed, skipping installation."
    } else {
        Write-Log "WhatsApp not found, installing..."
        Start-Process cmd.exe -ArgumentList '/c winget install --id "9NKSQGP7F2NH" --exact --source msstore --accept-source-agreements --silent --disable-interactivity --accept-package-agreements --no-upgrade' -Wait -NoNewWindow
        Write-Log "WhatsApp installation complete."
    }
	
    Remove-Item -Path $FilePath -Force

	Write-Log "Install done."
}

function Araid-upgrade-package {

    Clear-Host
	
    Write-Log "Upgrade started."
    Write-Host "Please wait..."

    Check-winget

	#clear pin list by force before adding our own list
	Start-Process cmd.exe -ArgumentList "/c winget pin reset --force" -Wait -NoNewWindow
	Write-Log "reset winget pin list --force"
	
    $pinapps = @(
        @{ id = "Microsoft.AppInstaller"; version = "1.23.191*" },
        @{ id = "Cisco.Webex"; version = "" },
        @{ id = "Microsoft.Edge"; version = "" },
        @{ id = "Microsoft.DevHome"; version = "" },
        @{ id = "Microsoft.OneDrive"; version = "" },
        @{ id = "Discord.Discord"; version = "" }
    )

    ForEach ($pinapp in $pinapps) {
        
        $id = $pinapp.id
        $version = $pinapp.version
        
        try {
            # Construct the winget pin command based on whether a version is provided
            $wingetCommand = if ($version) {
                "/c winget pin add --id $id --version `"$version`" --accept-source-agreements"
            } else {
                "/c winget pin add --id $id --blocking --accept-source-agreements"
            }
            
            Start-Process cmd.exe -ArgumentList $wingetCommand -Wait -NoNewWindow
            Write-Log "$id $version blocked from upgrade through winget"
        } catch {
            Write-Log "An error occurred while pinning ${id}: $_"
        }
    }

    try {
		Get-CimInstance -Namespace "Root\cimv2\mdm\dmmap" -ClassName "MDM_EnterpriseModernAppManagement_AppManagement01" | Invoke-CimMethod -MethodName UpdateScanMethod
        Start-Process cmd.exe -ArgumentList "/c winget upgrade --include-unknown --all --accept-package-agreements --accept-source-agreements --silent --disable-interactivity" -Wait -NoNewWindow
        Write-Log "Upgrade done."
    } catch {
        Write-Log "An error occurred during the upgrade: $_"
    }

}

function Araid-LegacyRepair {
	
	Clear-Host
	
	Write-Log "Legacy repair started. Recommend to run at least 2 times."
	Write-Host "Please wait..."

	# Disable Automatic Restart
	Write-Log "Disable Automatic Restart"
	$registryPath="HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl"
	$propertyName="AutoReboot"
	$value = 0
	Set-RegistryProperty -registryPath $registryPath -propertyName $propertyName -value $value
	
	# Clear console history
	$ConsoleHistory = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
	Write-Log "Clear console history"
	Remove-File "$ConsoleHistory"
	  
	Write-Log "Repair started"
	Write-Log "Started Dism Restore Health"
	Start-Process cmd.exe -ArgumentList "/c Dism /Online /Cleanup-Image /RestoreHealth" -Wait -NoNewWindow

<# 	# Start the job to monitor the CBS log
	$job = Start-Job -ScriptBlock {
		Get-Content -Path "$env:systemroot\Logs\CBS\CBS.log" -Tail 10 -Wait
	}

	# Start a new PowerShell console to display the job output
	Start-Process powershell.exe -ArgumentList "-NoExit", "-Command", "while (\$true) { Receive-Job -Id $job.Id; Start-Sleep -Seconds 5 }" #>

	Write-Log "Started System File Checker"
	Start-Process cmd.exe -ArgumentList "/c sfc /scannow" -Wait -NoNewWindow

<# 	Stop-Job -Id $job.Id
	Remove-Job -Id $job.Id #>
	
	$sourceFile = "$env:SystemRoot\Logs\CBS\CBS.log"
	$timestamp  = Get-Date -Format "yyMMddHHmmss"
	$pattern    = "\[SR\] Cannot repair member file"

	if (Test-Path -Path $sourceFile) {
		try {
			$unrepairables = Select-String -Path $sourceFile -Pattern $pattern

			if ($unrepairables) {
				$destinationFile = "$env:SystemRoot\araid\${timestamp}_SFCResults-Unrepairables.log"
				$unrepairables | Out-File -FilePath $destinationFile -Encoding UTF8
				Write-Log "Unrepairable files detected by SFC. Log created: $destinationFile" "Yellow"
			}
			else {
				Write-Log "No unrepairable files detected by SFC."
			}
		}
		catch {
			Write-Log "Error while processing SFC results: $_" "Red"
		}
	}
	else {
		Write-Log "CBS.log not found, unable to analyze SFC results." "Yellow"
	}
	
	#Write-Log "re-register all AppX packages for all users"
	#Get-AppXPackage -AllUsers | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Clear-Host
	Write-Log "Chkdsk on reboot"
    Start-Process cmd.exe -ArgumentList "/c echo y | chkdsk $env:homedrive /f" -Wait -NoNewWindow
	
	Read-Host -Prompt "Repair done. Press Enter to restart the computer..."
	
}

function Remove-RegistryPathAndLog {
    param(
        [string]$RegistryPath
    )

    # Check if the registry key path exists
    if (Test-Path -Path $RegistryPath) {
        # Remove the registry key
        try {
			Remove-Item -Path $RegistryPath -Recurse -Force -ErrorAction Stop
			Write-Log "Removed registry path $RegistryPath"
		} catch {
			Write-Log "Failed to remove registry path ${RegistryPath}: $_" "Yellow"
		}
    } else {
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
            Write-Log ("Removed property $PropertyName from registry path $RegistryPath")
        } else {
            Write-Log "Property $PropertyName does not exist at path $RegistryPath"
        }
    }
    else {
        Write-Log "Registry path $RegistryPath does not exist."
    }
}


Function Araid-CleanAndRestart {

	Clear-Host

	Write-Log "Cleaning started."
	Write-Host "Please wait..."

	Write-Log "Check if NahimicService exists"
	$service = Get-Service -Name "NahimicService" -ErrorAction SilentlyContinue

	if ($service) {
        if ($service.Status -eq 'Running') {
            Write-Log "Stopping NahimicService..."
            Stop-Service -Name "NahimicService" -Force -ErrorAction SilentlyContinue
        }

        Write-Log "Setting NahimicService to Disabled startup..."
        Set-Service -Name "NahimicService" -StartupType Disabled -ErrorAction SilentlyContinue

        # Confirm changes
        $updated = Get-Service -Name "NahimicService"
        Write-Log "Status: $($updated.Status), StartupType: Disabled"
	} else {
		Write-Log "NahimicService does not exist."
	}

	# Clear recycle bin
	Clear-RecycleBin -Force -ErrorAction SilentlyContinue
	Write-Log "Clear recycle bin"
	
	$shortcutsToKeep = @("Microsoft Edge.lnk", "File Explorer.lnk")
    
    $taskbarPath = "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
    $allShortcuts = Get-ChildItem -Path $taskbarPath -Filter *.lnk

    foreach ($shortcut in $allShortcuts) {
        if ($shortcutsToKeep -notcontains $shortcut.Name) {
			$shortcutPath = $shortcut.FullName
            try {
                Remove-File "$shortcutPath"
            }
            catch {
                Write-Log "Failed to remove: $($shortcut.Name). Error: $_"
            }
        }
    }
	
	# Show Taskbar
	$registryPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StuckRects3'
	$propertyName = 'Settings'

	# Get the current settings
	$currentSettings = Get-ItemProperty -Path $RegistryPath

	# Update the settings value (index 8) to 2
	$currentSettings.Settings[8] = 2

	Write-Log "Show Taskbar"
	Set-RegistryProperty -registryPath $registryPath -propertyName $propertyName -value $currentSettings.Settings

	# Show Desktop Icons
	Write-Log "Show Desktop Icons"
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

	Write-Log "Remove Recent in File Explorer Home"
	$registryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer'
	$propertyName = 'ShowRecent'
	$value = 0
	Set-RegistryProperty -registryPath $registryPath -propertyName $propertyName -value $value

	Write-Log "Remove Frequent Folders in Quick Access in File Explorer Home"
	$registryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer'
	$propertyName = 'ShowFrequent'
	$value = 0
	Set-RegistryProperty -registryPath $registryPath -propertyName $propertyName -value $value

	Write-Log "Turn Off Show Files from Office.com in File Explorer Home for Current User"
	$registryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer'
	$propertyName = 'ShowCloudFilesInQuickAccess'
	$value = 0
	Set-RegistryProperty -registryPath $registryPath -propertyName $propertyName -value $value

	#$registryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
	#$propertyName = 'DisableGraphRecentItems'
	#$value = 1
	#Set-RegistryProperty -registryPath $registryPath -propertyName $propertyName -value $value
	#Write-Log "Disable Show Files from Office.com in File Explorer Home for All Users"

	Write-Log "Open File Explorer to This PC"
	$registryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	$propertyName = 'LaunchTo'
	$value = 1
	Set-RegistryProperty -registryPath $registryPath -propertyName $propertyName -value $value
	
	Write-Log "Show hidden files, folders and drives"
	$registryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	$propertyName = 'Hidden'
	$value = 1
	Set-RegistryProperty -registryPath $registryPath -propertyName $propertyName -value $value

	Write-Log "Show This PC on desktop"
	$registryPath="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
	$propertyName="{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
	$value = 0
	Set-RegistryProperty -registryPath $registryPath -propertyName $propertyName -value $value

	Write-Log "Disable Automatic Restart"
	$registryPath="HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl"
	$propertyName="AutoReboot"
	$value = 0
	Set-RegistryProperty -registryPath $registryPath -propertyName $propertyName -value $value

	Write-Log "Changed debugging: Kernel memory dump"	
	$propertyName="CrashDumpEnabled"
	$value = 2
	Set-RegistryProperty -registryPath $registryPath -propertyName $propertyName -value $value

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

	# Disable Startup for skype
	$registryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'
	$propertyName = 'Skype for Desktop'
	Write-Log "Disable Startup for skype"
	Remove-RegistryPropertyAndLog -RegistryPath $registryPath -PropertyName $propertyName
	
	$registryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
	$propertyName = 'Skype for Desktop'
	Remove-RegistryPropertyAndLog -RegistryPath $registryPath -PropertyName $propertyName
	
	$registryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunNotification'
	$propertyName = 'StartupTNotiSkype for Desktop'
	Remove-RegistryPropertyAndLog -RegistryPath $registryPath -PropertyName $propertyName

	# Set wallpaper based on manufacturer
	$Manufacturers = @(
		"$env:systemroot\Web\Wallpaper\backgroundDefault.jpg",
		"$env:systemroot\Web\Wallpaper\Dell\BlueLava_1112000xx_inspiron_wallpaper58095_16x9_72dpi_RGB.jpg",
		"$env:systemroot\Web\Wallpaper\Dell\01.jpg",
		"$env:systemroot\Web\Wallpaper\Dell\Win7 Blue 1920x1200.jpg",
		"$env:systemroot\Web\Wallpaper\Dell\Win Blue 1920x1200.jpg",
		"$env:systemroot\Web\Wallpaper\Dell\Wallpaper_Vostro_M13.jpg",
		"$env:systemroot\Web\Wallpaper\Alienware\AW_ChromeHead_72dpi.jpg",
		"$env:systemroot\Web\Wallpaper\dell\AFX_FHD.png",
		"$env:systemroot\Web\Wallpaper\Hewlett-Packard Backgrounds\backgroundDefault.jpg",
		"$env:systemroot\Web\Wallpaper\HP Backgrounds\backgroundDefault.jpg",
		"$env:systemroot\System32\oobe\info\Wallpaper\backgroundDefault.jpg",
		"$env:systemroot\Web\Wallpaper\Lenovo\LenovoWallpaper.jpg",
		"$env:systemroot\Web\Wallpaper\Lenovo\Black Burst.jpg",
		"$env:systemroot\Web\Wallpaper\Lenovo\3.jpg",
		"$env:systemroot\ASUS\wallpapers\ASUS.jpg",
		"$env:systemroot\Web\Wallpaper\acer01.jpg",
		"$env:systemroot\Web\Wallpaper\WALLPAPER.jpg",
		"$env:systemroot\Web\Wallpaper\img0.jpg",
		"$env:systemroot\Web\Wallpaper\Surface\Surface.jpg",
		"$env:systemroot\Web\Wallpaper\MateBook\01.jpg",
		"$env:systemroot\Web\Wallpaper\Windows\img0.jpg"
	)

	foreach ($manufacturer in $Manufacturers) {
		if (Test-Path $manufacturer) {
			Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name Wallpaper -Value $manufacturer -Force
			RUNDLL32.EXE user32.dll,UpdatePerUserSystemParameters
			Write-Log "successfully changed wallpaper with $manufacturer"
			break
		}
	}

	# List all hidden devices
	$unknown_devs = Get-PnpDevice | Where-Object{$_.Status -eq 'Unknown'}

	if ($unknown_devs) {
		# Loop through all hidden devices to remove them
		ForEach($dev in $unknown_devs){
			try {
				# Run the command to remove the device
				Start-Process -FilePath "pnputil.exe" -ArgumentList "/remove-device $($dev.InstanceId)" -NoNewWindow -Wait
				# Log the successful removal
				Write-Log "$($dev.InstanceId) has been removed"
			}
			catch {
				# Log the error if the command fails
				Write-Log "Failed to remove $($dev.InstanceId): $_"
			}
		}
	} else {
		Write-Log "No Unknown devices to remove."
	}
	
	Clear-UserCacheFiles
	Clear-GlobalWindowsCache
	Clear-DuplicateOldDrivers
	
	Write-Log "Clear all event logs"
	wevtutil el | ForEach-Object {
		try {
			wevtutil cl $_
			Write-Log "Cleared event log: $_"
		} catch {
			Write-Log "Failed to clear log $_ : $_" "Yellow"
		}
	}

	
	#Write-Host "Further cleaning up windows update..."
	#Start-Process dism -ArgumentList "/online /cleanup-image /StartComponentCleanup /ResetBase" -Wait -NoNewWindow
	#Write-Log "dism /online /cleanup-image /StartComponentCleanup /ResetBase"
	
	#Start-Process cleanmgr.exe -ArgumentList "/d $env:homedrive" -Wait -NoNewWindow
	#Write-Log "cleanmgr /d $env:homedrive"
	
	# Define the desired install date
	#Write-log "Change installdate to current date"
	#$DesiredDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

	#$registryPath="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
	#$propertyName="InstallDate"
	#$value = [int][double]::Parse((Get-Date $DesiredDate -UFormat %s))
	#Set-RegistryProperty -registryPath $registryPath -propertyName $propertyName -value $value
	
	Set-SmbClientConfiguration -RequireSecuritySignature $false -Force
	Write-Log "Set-SmbClientConfiguration -RequireSecuritySignature false -Force"
	Set-SmbClientConfiguration -EnableInsecureGuestLogons $true -Force
	Write-Log "Set-SmbClientConfiguration -EnableInsecureGuestLogons true -Force"
	
	# Wait for user confirmation
	Read-Host -Prompt "Press Enter to restart the computer..."
	
}

function Stop-ServiceSafely {
    param(
        [Parameter(Mandatory)]
        [string]$ServiceName,

        [int]$TimeoutSeconds = 90
    )

    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-Log "Service $ServiceName not found" "Yellow"
        return $true
    }

    # Stop dependents first (gracefully)
    foreach ($dep in $svc.DependentServices) {
        if ($dep.Status -eq 'Running') {
            Write-Log "Stopping dependent service: $($dep.Name)"
            Stop-ServiceSafely -ServiceName $dep.Name -TimeoutSeconds 60
        }
    }

    Write-Log "Requesting stop for $ServiceName"
    Stop-Services -service $ServiceName -RetryCount 3 -RetryDelaySeconds 5

    # Wait for stop
    $elapsed = 0
    while ($elapsed -lt $TimeoutSeconds) {
        $status = (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue).Status
        if ($status -eq 'Stopped') {
            Write-Log "$ServiceName fully stopped"
            return $true
        }
        Start-Sleep -Seconds 2
        $elapsed += 2
    }

	Write-Log "Service $ServiceName cannot be safely stopped. Skipping to avoid system instability." "Yellow"
	return $false
}

function kill-necessary {

    $tasks = @(
        "explorer.exe","skype.exe","discord.exe","firefox.exe",
        "chrome.exe","msedge.exe","steam.exe","winword.exe","CiscoCollabHost.exe"
    )

    foreach ($task in $tasks) {
        try {
            Start-Process cmd.exe -ArgumentList "/c taskkill /f /im $task" -NoNewWindow -Wait
            Write-Log "Task killed: $task"
        } catch {
            Write-Log "Failed to kill task ${task}: $_" "Yellow"
        }
    }

    # Order matters (least risky → most risky)
    $services = @(
        "bits",
        "dosvc",
        "wuauserv"
    )

    foreach ($svc in $services) {
        Stop-ServiceSafely -ServiceName $svc -TimeoutSeconds 120
    }

    Write-Log "Kill necessary process done."
}

Function Close-OfficeApps {
    $apps = @("WINWORD","MSACCESS","EXCEL","ONENOTE","OUTLOOK","POWERPNT","MSPUB")
    foreach ($app in $apps) {
        $proc = Get-Process -Name $app -ErrorAction SilentlyContinue
        if ($proc) {
            Stop-Process -Name $app -Force -ErrorAction SilentlyContinue
            Write-Log "Closed $app"
        }
    }
}

Function Set-OEMRegistry {
    $paths = @(
        "HKLM:\SOFTWARE\Microsoft\Office\16.0\Common\OEM",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Office\16.0\Common\OEM"
    )
    foreach ($p in $paths) {
        if (!(Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
        Set-ItemProperty -Path $p -Name OOBEMode -Value "OEMTA"
        Write-Log "Set OOBEMode at $p"
    }
}

Function Is-WindowsActivated {
    try {
        $status = Get-CimInstance -Class SoftwareLicensingProduct `
            | Where-Object { $_.PartialProductKey -and $_.LicenseStatus -eq 1 }
        return $status -ne $null
    } catch {
        return $false
    }
}

Function Activate-Office {
    $officePaths = @(
        "$env:ProgramFiles\Microsoft Office\root\Office16"
    )

    if ($env:ProgramFiles -and ${env:ProgramFiles(x86)}) {
        $officePaths += "${env:ProgramFiles(x86)}\Microsoft Office\root\Office16"
    }

    foreach ($p in $officePaths) {
        $ospp = Join-Path $p "OSPP.VBS"
        if (Test-Path $ospp) {
            cscript.exe $ospp /act | Out-Null
            Write-Log "Triggered Office activation at $p"
        }
    }
}

Function Move-Pagefile {
    param(
        [Parameter(Mandatory)]
        [string]$Drive,
        [int]$InitialSize = 4096,
        [int]$MaximumSize = 8192
    )

    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"

    try {
        Write-Log "Configuring pagefile on $Drive"

        Set-ItemProperty -Path $regPath -Name AutomaticManagedPagefile -Value 0 -Type DWord

        $newPagefile = @("$Drive\pagefile.sys $InitialSize $MaximumSize")

        Set-ItemProperty -Path $regPath -Name PagingFiles -Value $newPagefile -Type MultiString

        Write-Log "Pagefile set to $Drive\pagefile.sys ($InitialSize MB - $MaximumSize MB)"
        Write-Log "Reboot required for pagefile changes to take effect" "Yellow"

        return $true
    }
    catch {
        Write-Log "Failed to configure pagefile: $_" "Red"
        return $false
    }
}

Function Cleanup-OldPagefiles {
    Get-ChildItem -Path "C:\" -Filter "pagefile.sys" -Force -ErrorAction SilentlyContinue |
        ForEach-Object {
            Write-Log "Old pagefile detected: $($_.FullName) (will be removed on reboot)"
        }
}

function Move-Folder {

    $foldersToMove = @(
        @{ Source = "$env:homedrive\MSOCache"; DestinationRoot = "D:\homedrive" },
        @{ Source = "$env:systemroot\SoftwareDistribution"; DestinationRoot = "D:\systemroot"; Service = "wuauserv" },
        @{ Source = "$env:systemroot\Temp"; DestinationRoot = "D:\systemroot" },
        @{ Source = "$env:systemroot\LiveKernelReports"; DestinationRoot = "D:\systemroot" },
		@{ Source = "$env:ProgramData\Package Cache"; DestinationRoot = "D:\ProgramData\Package Cache" },
		#@{ Source = "$env:systemroot\Installer"; DestinationRoot = "D:\systemroot"; Service = "TrustedInstaller" } #msi installer will fail
        #@{ Source = "$env:systemroot\System32\winevt\Logs"; DestinationRoot = "D:\systemroot\System32\winevt\Logs"; Service = "EventLog" }, #always fail
        #@{ Source = "$env:ProgramData\Microsoft\Windows\WER"; DestinationRoot = "D:\ProgramData\Microsoft\Windows"; Service = "EventLog" } #always fail
		@{ Source = "$env:systemroot\Logs"; DestinationRoot = "D:\systemroot" }
    )

    foreach ($folder in $foldersToMove) {
        $source = $folder.Source
        $destinationRoot = $folder.DestinationRoot
		$Service = $folder.Service
		
        if (Test-Path -Path $source) {
            try {
				# Stop the associated service if needed
				if (-not [string]::IsNullOrEmpty($Service)) {
					Stop-ServiceSafely -ServiceName $Service -TimeoutSeconds 120
				}
				
                $folderName = [System.IO.Path]::GetFileName($source.TrimEnd('\'))
                $destination = Join-Path -Path $destinationRoot -ChildPath $folderName
                
                # Move the folder
                if (-not (Test-Path -Path $destination)) {
                    Move-Item -Path $source -Destination $destination -Force -ErrorAction Stop
                    Write-Log "Moved $source to $destination"
                }

                # Create junction
                Start-Process cmd.exe -ArgumentList "/c MKLINK /J ""$source"" ""$destination""" -NoNewWindow -Wait
                Write-Log "MKLINK /J $source $destination"
					
            } catch {
                Write-Log "Error moving ${source}: $_"
            }
        }
    }
	
	if (Test-Path "D:\") {
		Move-Pagefile -Drive "D:"
		Write-Log "Pagefile moved successfully. Please reboot the system."
	} else {
		Write-Log "Drive D: not found. Pagefile move skipped." "Yellow"
	}

    Write-Log "Move folder done."
}

Function OEMofficeActivation {
	
	Clear-Host

	Write-Log "Starting OEM Office Activation..."
	Write-Host "Please wait..."
	
	# Clear console history
	$ConsoleHistory = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
	Write-Log "Clear console history"
	Remove-File "$ConsoleHistory"
	$oem = $false
	
	# Check Windows activation
    if (Is-WindowsActivated) {
        Write-Log "Windows is already activated."
		$oem = $true
    } else {
        Write-Log "Windows is not activated. Installing OEM SLP key from BIOS..."
        $OEMKey = (Get-WmiObject -Query 'select * from SoftwareLicensingService').OA3xOriginalProductKey

        if ($OEMKey) {
            Write-Log "Detected OEM SLP Key: $OEMKey"
            Start-Process -FilePath "cscript.exe" -ArgumentList "/Nologo C:\Windows\System32\slmgr.vbs /ipk $OEMKey" -Wait
            Start-Process -FilePath "cscript.exe" -ArgumentList "/Nologo C:\Windows\System32\slmgr.vbs /ato" -Wait
            Write-Log "Windows activation attempted."
			$oem = $true
        } else {
            Write-Log "No OEM SLP key found in BIOS. Activation skipped."
			$oem = $false
        }
    }
	
	if ($oem) {
		# Activate Office
		Close-OfficeApps
		Set-OEMRegistry
		Activate-Office
		Write-Log "OEM Office Activation Completed."
	} else {
		Write-Log "Non-OEM system detected. Office activation skipped."
	}
	
	# Wait for user confirmation
	Read-Host -Prompt "Press Enter to restart the computer..."
}

Clear-Host
kill-necessary

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
        public const int WS_THICKFRAME = 0x00040000; // disable resize
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
$form.Size = New-Object System.Drawing.Size(480, 430)
$form.TopMost = $true

# Remove minimize, maximize, close buttons and disable form resize
$form.Add_Shown({
    $hWnd = $form.Handle
    $currentStyle = [Win32]::GetWindowLong($hWnd, [Win32]::GWL_STYLE)
    $newStyle = $currentStyle -band -bnot ([Win32]::WS_SYSMENU) -band -bnot ([Win32]::WS_THICKFRAME)
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
    $result = [System.Windows.Forms.MessageBox]::Show("No Ragrets?", "Confirmation", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
    if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
        $allowClose = $true
		$Form.Close()
        Araid-CleanAndRestart
    }
})

# Create label for Legacy Repair
$label4 = New-Object System.Windows.Forms.Label
$label4.Text = "Legacy Repair and reboot"
$label4.Location = New-Object System.Drawing.Point(270, 220)
$label4.Size = New-Object System.Drawing.Size(190, 20)

# Create button for Legacy Repair
$button4 = New-Object System.Windows.Forms.Button
$button4.Text = "Legacy Repair"
$button4.Location = New-Object System.Drawing.Point(50, 210)
$button4.Size = New-Object System.Drawing.Size(190, 30)
$button4.Add_Click({
	$allowClose = $true
	$Form.Close()
	Araid-LegacyRepair
})

# Create label for Move Folder
$label5 = New-Object System.Windows.Forms.Label
$label5.Text = "Move Folder to D:\"
$label5.Location = New-Object System.Drawing.Point(270, 280)
$label5.Size = New-Object System.Drawing.Size(190, 20)

# Create button for Move Folder
$button5 = New-Object System.Windows.Forms.Button
$button5.Text = "Move Folder to D:\"
$button5.Location = New-Object System.Drawing.Point(50, 270)
$button5.Size = New-Object System.Drawing.Size(190, 30)
$button5.Add_Click({
	Move-Folder
})

# Create label for OEMofficeActivation
$label6 = New-Object System.Windows.Forms.Label
$label6.Text = "OEM office Activation"
$label6.Location = New-Object System.Drawing.Point(270, 340)
$label6.Size = New-Object System.Drawing.Size(190, 20)

# Create button for OEMofficeActivation
$button6 = New-Object System.Windows.Forms.Button
$button6.Text = "OEMofficeActivation"
$button6.Location = New-Object System.Drawing.Point(50, 330)
$button6.Size = New-Object System.Drawing.Size(190, 30)
$button6.Add_Click({
	OEMofficeActivation
})

# Add buttons to the form
$form.Controls.Add($label1)
$form.Controls.Add($button1)
$form.Controls.Add($label2)
$form.Controls.Add($button2)
$form.Controls.Add($label3)
$form.Controls.Add($button3)
$form.Controls.Add($label4)
$form.Controls.Add($button4)
$form.Controls.Add($label5)
$form.Controls.Add($button5)
$form.Controls.Add($label6)
$form.Controls.Add($button6)

# Show the form
$form.ShowDialog()