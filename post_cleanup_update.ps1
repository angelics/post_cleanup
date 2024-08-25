Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$global:wingetChecked = $false

$log = "$env:systemroot\Logs\araid\araid_post.log"

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
    Remove-SubFile "$env:ProgramData\Microsoft\Windows Defender\Scans\mpcache-*.bin"
    Remove-SubFile "$env:ProgramData\Microsoft\Windows Defender\Scans\mpcache-*.log"
}

function Stop-Services {
    
    param (
        [Parameter(Mandatory = $true)][string]$service,
        [int]$RetryCount = 3,
        [int]$RetryDelaySeconds = 5
    )

    $attempt = 0
    while ($attempt -lt $RetryCount) {
        try {
            $serviceStatus = (Get-Service -Name $service).Status

            if ($serviceStatus -eq 'Running') {
                Write-Host "Attempting to stop $service... (Attempt $($attempt + 1))"

                # Get and stop dependent services first
                $dependentServices = Get-Service -Name $service | Select-Object -ExpandProperty DependentServices
                foreach ($dep in $dependentServices) {
                    if ($dep.Status -eq 'Running') {
                        Write-Host "Stopping dependent service: $($dep.Name)"
                        Stop-Service -Name $dep.Name -Force
                        # Optionally, you can add a loop to retry stopping the dependent service as well.
                    }
                }

                # Stop the main service
                Stop-Service -Name $service -Force

                # Check if the service is stopped after the attempt
                if ((Get-Service -Name $service).Status -eq 'Stopped') {
                    Write-Host "$service stopped successfully."
                    return  # Exit the function if successful
                }
            } else {
                Write-Host "$service is already stopped."
                return  # Exit the function if the service is not running
            }

        } catch {
            Write-Host "Attempt $($attempt + 1) to stop $service failed. Retrying in $RetryDelaySeconds seconds..."
            Start-Sleep -Seconds $RetryDelaySeconds
        }

        $attempt++
    }

    # After retry attempts, throw an error if the service is still running
    if ((Get-Service -Name $service).Status -eq 'Running') {
        throw "Failed to stop $service after $RetryCount attempts."
    }
}

function Start-Services {

    param (
        [Parameter(Mandatory = $true)][string]$service,
        [int]$RetryCount = 3,
        [int]$RetryDelaySeconds = 5
    )

    try {
        # Check if the service's start type is 'Disabled'
        $serviceController = Get-WmiObject -Class Win32_Service -Filter "Name='$service'"
        if ($serviceController.StartMode -eq 'Disabled') {
            Write-Host "$service is disabled and will not be started."
            return
        }

        # Check and start dependent services first
        $dependentServices = Get-Service -Name $service | Select-Object -ExpandProperty DependentServices
        foreach ($dep in $dependentServices) {
            if ($dep.Status -eq 'Stopped') {
                Write-Host "Starting dependent service: $($dep.Name)"
                Start-Service -Name $dep.Name
                # Optionally, you can add retry logic here if necessary.
            }
        }

        # Check the current status of the service
        if ((Get-Service -Name $service).Status -eq 'Stopped') {
            $attempt = 0
            while ($attempt -lt $RetryCount) {
                try {
                    Write-Host "Attempting to start $service... (Attempt $($attempt + 1))"
                    Start-Service -Name $service

                    # Check if the service is running after the attempt
                    if ((Get-Service -Name $service).Status -eq 'Running') {
                        Write-Host "$service started successfully."
                        return  # Exit the function if successful
                    }
                } catch {
                    Write-Host "Attempt $($attempt + 1) to start $service failed. Retrying in $RetryDelaySeconds seconds..."
                    Start-Sleep -Seconds $RetryDelaySeconds
                }

                $attempt++
            }

            # After retry attempts, throw an error if the service is still stopped
            if ((Get-Service -Name $service).Status -eq 'Stopped') {
                throw "Failed to start $service after $RetryCount attempts."
            }
        } else {
            Write-Host "$service is already running."
        }
    } catch {
        Write-Host "Failed to start service: $_"
    }
}

function Clear-WindowsUpdateCache {
	
    Stop-Services -service "wuauserv" -RetryCount 3 -RetryDelaySeconds 5

	Remove-SubFile "$env:systemroot\SoftwareDistribution\Download"
	Write-Log "Windows Update cache files deleted."

	Start-Services -service "wuauserv" -RetryCount 3 -RetryDelaySeconds 5
	
}

function Clear-WindowsSearch {
	
	#$env:WINDIR = C:\Windows
	
    Stop-Services -service "WSearch" -RetryCount 3 -RetryDelaySeconds 5

	# Delete Windows Search cache files
	Remove-Item -Path "$env:LOCALAPPDATA\Packages\Microsoft.Windows.Client.CBS_*\LocalState\Search" -Recurse -Force -ErrorAction Stop
	Write-Log "Deleted Windows Search cache files"

	Start-Services -service "WSearch" -RetryCount 3 -RetryDelaySeconds 5
	
}

Function Remove-SubFile
{
    param([Parameter(Mandatory = $true)][string]$path)

    if ((Test-Path "$path"))
    {
        Get-ChildItem -Path "$path" -Force -Recurse -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
		Write-Log "SubFile removed $path"
    }
}

Function Remove-File
{
    param([Parameter(Mandatory = $true)][string]$path)

    if ((Test-Path "$path"))
    {
        Remove-Item -Path "$path" -Recurse -Force -ErrorAction SilentlyContinue
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
			Remove-SubFile "$path\$cachePath"
		}
		$possibleCacheFiles = @("config.xml", "session.xml")
		ForEach ($cacheFile in $possibleCacheFiles) {
			Remove-File "$path\$cacheFile"
		}
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
				Start-Process pnputil.exe -ArgumentList "/delete-driver $Name" -Wait
				Write-Host "Successfully removed driver: Name=$Name, FileName=$FileName, Vendor=$Vendor, Date=$Date, ClassName=$ClassName, Version=$Version, Entr=$Entr"
				Write-Log "Successfully removed driver: Name=$Name, FileName=$FileName, Vendor=$Vendor, Date=$Date, ClassName=$ClassName, Version=$Version, Entr=$Entr"
			} catch {
				Write-Log "Failed to remove driver: Name=$Name, FileName=$FileName, Vendor=$Vendor, Date=$Date, ClassName=$ClassName, Version=$Version, Entr={$Entr}. Error: $_"
			}
		}
	} else {
        Write-Host "No old or duplicate drivers to remove."
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
    
    # Check if winget is installed
    $wingetInstalled = Get-Command winget -ErrorAction SilentlyContinue
    if ($wingetInstalled) {
        $wingetVersion = Get-WingetVersion
    } else {
        $wingetVersion = [version]"0.0" # Dummy version for non-installed case
    }

    # Define the minimum required version
    $minVersion = [version]"1.6"
    
    # Install or upgrade winget if necessary
    if ($wingetVersion -lt $minVersion) {
        # Install winget
		# https://github.com/microsoft/winget-cli/issues/1861#issuecomment-1634057674
        IWR -Uri "https://github.com/microsoft/terminal/releases/download/v1.19.10302.0/Microsoft.WindowsTerminal_1.19.10302.0_8wekyb3d8bbwe.msixbundle_Windows10_PreinstallKit.zip" -OutFile ".\Windows10_PreinstallKit.zip"
        Expand-Archive -Path ".\Windows10_PreinstallKit.zip" -DestinationPath ".\Windows10_PreinstallKit" -Force
        Move-Item -Path ".\Windows10_PreinstallKit\Microsoft.UI.Xaml.2.8_8.2310.30001.0_x64__8wekyb3d8bbwe.appx" -Destination . -Force
        Remove-Item -Path ".\Windows10_PreinstallKit.zip" -Force
        Remove-Item -Path ".\Windows10_PreinstallKit" -Recurse -Force
        Add-AppxPackage -Path ".\Microsoft.UI.Xaml.2.8_8.2310.30001.0_x64__8wekyb3d8bbwe.appx" -ForceApplicationShutdown
        Remove-Item -Path ".\Microsoft.UI.Xaml.2.8_8.2310.30001.0_x64__8wekyb3d8bbwe.appx" -Force
        Add-AppxPackage -Path "https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx" -ForceApplicationShutdown
        Add-AppxPackage -Path "https://aka.ms/getwinget" -ForceApplicationShutdown
    }
		
    $global:wingetChecked = $true
}

Function Araid-install-package {
	
	Clear-Host
	
	Write-Host "install started."
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

	Write-Host "Install done."
}

function Araid-upgrade-package {
	
	Clear-Host
	
	Write-Host "upgrade started."
	Write-Host "Please wait..."
	
	Check-winget
	
	$pinapps = @(
        "Discord.Discord",
        "Microsoft.DevHome",
        "Microsoft.Edge",
        "Cisco.Webex"
    )
	
	ForEach ($pinapp in $pinapps){
		try {
			Start-Process cmd.exe -ArgumentList "/c winget pin add --id $pinapp --blocking --accept-source-agreements" -Wait -NoNewWindow
			Write-Log "$pinapp blocked from upgrade through winget"
		} catch {
			Write-Log "An error occurred: $_"
		}
	}
	
	try {
        Start-Process cmd.exe -ArgumentList "/c winget upgrade --all --accept-package-agreements --accept-source-agreements --silent --disable-interactivity" -Wait -NoNewWindow
        Write-Host "Upgrade done."
    } catch {
        Write-Log "An error occurred: $_"
    }
	
}

function Araid-LegacyRepair {
	
	Clear-Host
	
	Write-Host "Legacy repair started. Recommend to run at least 2 times."
	Write-Host "Please wait..."
	
	# Disable Automatic Restart
	$registryPath="HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl"
	$propertyName="AutoReboot"
	$value = 0
	Set-RegistryProperty -registryPath $registryPath -propertyName $propertyName -value $value
	Write-Log "Disable Automatic Restart"
	
	# Clear console history
	$ConsoleHistory = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
	Write-Log "Clear console history"
	Remove-File "$ConsoleHistory"
	
	$sfcscanlog = "$env:systemroot\Logs\araid\scanlog.txt"
	Remove-File "$sfcscanlog"
	  
	Write-Host "Repair started"
	Write-Log "Started Dism Restore Health"
	Start-Process cmd.exe -ArgumentList "/c Dism /Online /Cleanup-Image /RestoreHealth" -Wait -NoNewWindow

	# Start the job to monitor the CBS log
	$job = Start-Job -ScriptBlock {
		Get-Content -Path "$env:systemroot\Logs\CBS\CBS.log" -Tail 10 -Wait
	}

	# Start a new PowerShell console to display the job output
	Start-Process powershell.exe -ArgumentList "-NoExit", "-Command", "while (\$true) { Receive-Job -Id $job.Id; Start-Sleep -Seconds 5 }"

	Write-Log "Started System File Checker"
	Start-Process cmd.exe -ArgumentList "/c sfc /scannow" -Wait -NoNewWindow

	Stop-Job -Id $job.Id
	Remove-Job -Id $job.Id
	
	$sourceFile = "$env:systemroot\Logs\CBS\CBS.log"
	$timestamp = Get-Date -Format "yyMMddHHmmss"
	$destinationFile = "$env:systemroot\Logs\araid\{$timestamp}_SFCResults-Unrepairables.log"
	$pattern = "\[SR\] Cannot repair member file"

	if (Test-Path -Path $sourceFile) {
		try {
			Select-String -Path $sourceFile -Pattern $pattern | Out-File -FilePath $destinationFile
			if ((Get-Content -Path $destinationFile).Length -gt 0) {
                Write-Host "There are unrepairable files detected by SFC."
                Write-Log "There are unrepairable files detected by SFC."
            } else {
                Write-Host "No unrepairable files detected by SFC."
            }
		}
		catch {
			Write-Log "An error occurred: $_"
		}
	}
	
	Write-Log "re-register all AppX packages for all users"
	Get-AppXPackage -AllUsers | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
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
        Remove-Item -Path $RegistryPath -Recurse -Force
        Write-Log ("Removed registry path $RegistryPath.")
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

	Write-Host "Cleaning started."
	Write-Host "Please wait..."

	# Clear recycle bin
	Clear-RecycleBin -Force -ErrorAction SilentlyContinue
	Write-Log "Clear recycle bin"
	
	Clear-Taskbar
	
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

	# Show This PC on desktop
	$registryPath="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
	$propertyName="{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
	$value = 0
	Set-RegistryProperty -registryPath $registryPath -propertyName $propertyName -value $value
	Write-Log "Show This PC on desktop"
	
	# Disable Automatic Restart
	$registryPath="HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl"
	$propertyName="AutoReboot"
	$value = 0
	Set-RegistryProperty -registryPath $registryPath -propertyName $propertyName -value $value
	Write-Log "Disable Automatic Restart"
	
	$propertyName="CrashDumpEnabled"
	$value = 2
	Set-RegistryProperty -registryPath $registryPath -propertyName $propertyName -value $value
	Write-Log "Changed debugging: Kernel memory dump"

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
		Write-Host "No Unknown devices to remove."
	}
	
	Clear-UserCacheFiles
	Clear-GlobalWindowsCache
	Clear-DuplicateOldDrivers
	
	Write-Host "Clear all event logs"
	Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }
	Write-Log "Clear all event logs"
	
	#Write-Host "Further cleaning up windows update..."
	#Start-Process dism -ArgumentList "/online /cleanup-image /StartComponentCleanup /ResetBase" -Wait -NoNewWindow
	#Write-Log "dism /online /cleanup-image /StartComponentCleanup /ResetBase"
	
	#Start-Process cleanmgr.exe -ArgumentList "/d $env:homedrive" -Wait -NoNewWindow
	#Write-Log "cleanmgr /d $env:homedrive"
	
	# Wait for user confirmation
	Read-Host -Prompt "Press Enter to restart the computer..."
	
}

function kill-necessary {
	
    $tasks = @("explorer.exe", "skype.exe", "discord.exe", "firefox.exe", "chrome.exe", "msedge.exe", "steam.exe", "winword.exe", "CiscoCollabHost.exe")

    foreach ($task in $tasks) {
        $command = "taskkill /f /im $task"

        try {
            Start-Process cmd.exe -ArgumentList "/c $command" -NoNewWindow -Wait
            Write-Log "Task killed: $task"
        }
        catch {
            Write-Log "Error occurred while trying to kill task {$task}: $_"
        }
    }
	
}

function Clear-Taskbar {
    $shortcutsToKeep = @("Microsoft Edge.lnk", "File Explorer.lnk")
    
    $taskbarPath = "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
    $allShortcuts = Get-ChildItem -Path $taskbarPath -Filter *.lnk

    foreach ($shortcut in $allShortcuts) {
        if ($shortcutsToKeep -notcontains $shortcut.Name) {
            try {
                Remove-File "$shortcut.FullName"
                Write-Log "Remove-File $shortcut.FullName"
                Write-Log "Removed: $($shortcut.Name)"
            }
            catch {
                Write-Log "Failed to remove: $($shortcut.Name). Error: $_"
            }
        }
    }
}

function Move-Pagefile {
    param (
        [string]$NewPagefileDrive = "D:",
        [int]$InitialSize = $null,
        [int]$MaxSize = $null
    )

    # Path to the registry key for pagefile configuration
    $pagefileRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"

    try {
        # Check if the registry key exists
        if (!(Test-Path $pagefileRegPath)) {
            Write-Warning "Registry key $pagefileRegPath not found."
            return $false
        }

        # Get current pagefile configuration
        $currentConfig = Get-ItemProperty -Path $pagefileRegPath -Name "PagingFiles"
        $currentPagingFiles = $currentConfig.PagingFiles

        # Determine initial and maximum sizes
        if ($null -eq $InitialSize) {
            $initialSize = $currentPagingFiles.Split(' ')[1]
        }
        if ($null -eq $MaxSize) {
            $maxSize = $currentPagingFiles.Split(' ')[2]
        }

        # Set the new pagefile location with specified sizes
        $newPagefile = "$NewPagefileDrive\pagefile.sys"
        $newPagingFileConfig = "$newPagefile $initialSize $maxSize"

        # Update the registry key with the new settings
        Set-ItemProperty -Path $pagefileRegPath -Name "PagingFiles" -Value $newPagingFileConfig

        Write-Log "Pagefile has been moved to $NewPagefileDrive. A system reboot is required."
        return $true
    } catch [System.Exception] {
        Write-Log "An error occurred while moving the pagefile: $($_.Exception.Message)"
        return $false
    }
}

function Move-Folder {

    $foldersToMove = @(
        @{ Source = "$env:homedrive\MSOCache"; DestinationRoot = "D:\homedrive" },
        @{ Source = "$env:systemroot\SoftwareDistribution"; DestinationRoot = "D:\systemroot"; Service = "wuauserv" },
        @{ Source = "$env:systemroot\Temp"; DestinationRoot = "D:\systemroot" },
        @{ Source = "$env:systemroot\LiveKernelReports"; DestinationRoot = "D:\systemroot" },
		@{ Source = "$env:systemroot\Installer"; DestinationRoot = "D:\systemroot"; Service = "TrustedInstaller" }
        #@{ Source = "$env:systemroot\System32\winevt\Logs"; DestinationRoot = "D:\systemroot\System32\winevt\Logs"; Service = "EventLog" }, #always fail
        #@{ Source = "$env:ProgramData\Microsoft\Windows\WER"; DestinationRoot = "D:\ProgramData\Microsoft\Windows"; Service = "EventLog" } #always fail
		#@{ Source = "$env:systemroot\Logs"; DestinationRoot = "D:\systemroot" }, write-log folder
    )

    foreach ($folder in $foldersToMove) {
        $source = $folder.Source
        $destinationRoot = $folder.DestinationRoot
		$Service = $folder.Service
		
        if (Test-Path -Path $source) {
            try {
				# Stop the associated service if needed
				if (-not [string]::IsNullOrEmpty($Service)) {
					Stop-Services -service $Service -RetryCount 3 -RetryDelaySeconds 5
				}
				
                $folderName = [System.IO.Path]::GetFileName($source.TrimEnd('\'))
                $destination = Join-Path -Path $destinationRoot -ChildPath $folderName
                
                # Move the folder
                if (-not (Test-Path -Path $destination)) {
                    Move-Item -Path $source -Destination $destination -Force -Verbose
                    Write-Log "Moved $source to $destination"
                }

                # Create junction
                Start-Process cmd.exe -ArgumentList "/c MKLINK /J $source $destination" -NoNewWindow -Wait
                Write-Log "MKLINK /J $source $destination"
				
				# Start the associated service if it was stopped
				if (-not [string]::IsNullOrEmpty($Service)) {
					Start-Services -service $Service -RetryCount 3 -RetryDelaySeconds 5
				}		
            } catch {
                Write-Log "Error moving ${source}: $_"
            }
        }
    }

    # Handle the pagefile
    if (Move-Pagefile -NewPagefileDrive "D:\") {
        Write-Host "Pagefile moved successfully. Please reboot the system."
    } else {
        Write-Host "Pagefile move failed. Check the error message."
    }

    Write-Host "Move folder done."
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
$form.Size = New-Object System.Drawing.Size(480, 370)
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

# Show the form
$form.ShowDialog()