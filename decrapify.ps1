##########
# Win10 Initial Setup Script
# Author: Disassembler <disassembler@dasm.cz>
# Version: 1.4, 2016-01-16
##########

# Ask for elevated permissions if required
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
	Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
	Exit
}



##########
# Privacy Settings
##########

# Disable Telemetry
Write-Host "Disabling Telemetry..."
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0

# Enable Telemetry
# Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry"

# Disable Wi-Fi Sense
Write-Host "Disabling Wi-Fi Sense..."
If (!(Test-Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
	New-Item -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0

# Enable Wi-Fi Sense
# Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 1
# Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 1

# Disable SmartScreen Filter
Write-Host "Disabling SmartScreen Filter..."
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Type String -Value "Off"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Type DWord -Value 0

# Enable SmartScreen Filter
# Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Type String -Value "RequireAdmin"
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation"

# Disable Bing Search in Start Menu
Write-Host "Disabling Bing Search in Start Menu..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0

# Enable Bing Search in Start Menu
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled"

# Disable Location Tracking
Write-Host "Disabling Location Tracking..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0

# Enable Location Tracking
# Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 1
# Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 1

# Disable Feedback
Write-Host "Disabling Feedback..."
If (!(Test-Path "HKCU:\Software\Microsoft\Siuf\Rules")) {
	New-Item -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0

# Enable Feedback
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod"

# Disable Advertising ID
Write-Host "Disabling Advertising ID..."
If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo")) {
	New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type DWord -Value 0

# Enable Advertising ID
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled"

# Disable Cortana
Write-Host "Disabling Cortana..."
If (!(Test-Path "HKCU:\Software\Microsoft\Personalization\Settings")) {
	New-Item -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
If (!(Test-Path "HKCU:\Software\Microsoft\InputPersonalization")) {
	New-Item -Path "HKCU:\Software\Microsoft\InputPersonalization" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
If (!(Test-Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore")) {
	New-Item -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0

# Enable Cortana
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy"
# Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 0
# Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 0
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts"

# Restrict Windows Update P2P only to local network
Write-Host "Restricting Windows Update P2P only to local network..."
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 1
If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization")) {
	New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Name "SystemSettingsDownloadMode" -Type DWord -Value 3

# Unrestrict Windows Update P2P
# Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode"
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Name "SystemSettingsDownloadMode"

# Remove AutoLogger file and restrict directory
Write-Host "Removing AutoLogger file and restricting directory..."
$autoLoggerDir = "$env:PROGRAMDATA\Microsoft\Diagnosis\ETLLogs\AutoLogger"
If (Test-Path "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl") {
	Remove-Item "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl"
}
icacls $autoLoggerDir /deny SYSTEM:`(OI`)`(CI`)F | Out-Null

# Unrestrict AutoLogger directory
# $autoLoggerDir = "$env:PROGRAMDATA\Microsoft\Diagnosis\ETLLogs\AutoLogger"
# icacls $autoLoggerDir /grant:r SYSTEM:`(OI`)`(CI`)F | Out-Null

# Stop and disable Diagnostics Tracking Service
Write-Host "Stopping and disabling Diagnostics Tracking Service..."
Stop-Service "DiagTrack"
Set-Service "DiagTrack" -StartupType Disabled

# Enable and start Diagnostics Tracking Service
# Set-Service "DiagTrack" -StartupType Automatic
# Start-Service "DiagTrack"

##########
# Service Tweaks
##########

# Lower UAC level
# Write-Host "Lowering UAC level..."
# Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 0
# Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 0

# Raise UAC level
# Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 5
# Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 1

# Enable sharing mapped drives between users
# Write-Host "Enabling sharing mapped drives between users..."
# Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections" -Type DWord -Value 1

# Disable sharing mapped drives between users
# Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections"

# Disable Firewall
# Write-Host "Disabling Firewall..."
# Set-NetFirewallProfile -Profile * -Enabled False

# Enable Firewall
# Set-NetFirewallProfile -Profile * -Enabled True

# Disable Windows Defender
# Write-Host "Disabling Windows Defender..."
# Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 1

# Enable Windows Defender
# Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware"

# Disable Windows Update automatic restart
Write-Host "Disabling Windows Update automatic restart..."
Set-ItemProperty -Path "HKLM:\Software\Microsoft\WindowsUpdate\UX\Settings" -Name "UxOption" -Type DWord -Value 1

# Enable Windows Update automatic restart
# Set-ItemProperty -Path "HKLM:\Software\Microsoft\WindowsUpdate\UX\Settings" -Name "UxOption" -Type DWord -Value 0

# Stop and disable Home Groups services
Write-Host "Stopping and disabling Home Groups services..."
Stop-Service "HomeGroupListener"
Set-Service "HomeGroupListener" -StartupType Disabled
Stop-Service "HomeGroupProvider"
Set-Service "HomeGroupProvider" -StartupType Disabled

# Enable and start Home Groups services
# Set-Service "HomeGroupListener" -StartupType Manual
# Set-Service "HomeGroupProvider" -StartupType Manual
# Start-Service "HomeGroupProvider"

# Disable Remote Assistance
# Write-Host "Disabling Remote Assistance..."
# Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0

# Enable Remote Assistance
# Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 1

# Enable Remote Desktop w/o Network Level Authentication
# Write-Host "Enabling Remote Desktop w/o Network Level Authentication..."
# Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 0
# Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Type DWord -Value 0

# Disable Remote Desktop
# Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 1
# Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Type DWord -Value 1

##########
# UI Tweaks
##########

# Disable Action Center
# Write-Host "Disabling Action Center..."
# If (!(Test-Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer")) {
#	New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" | Out-Null
# }
# Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -Type DWord -Value 1
# Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Type DWord -Value 0

# Enable Action Center
# Remove-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter"
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled"

# Disable Lock screen
# Write-Host "Disabling Lock screen..."
# If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\Personalization")) {
# 	New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\Personalization" | Out-Null
# }
# Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -Type DWord -Value 1

# Enable Lock screen
# Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen"

# Disable Autoplay
# Write-Host "Disabling Autoplay..."
# Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 1

# Enable Autoplay
# Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 0

# Disable Autorun for all drives
# Write-Host "Disabling Autorun for all drives..."
# If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
#	New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
#}
# Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 255

# Enable Autorun
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun"

# Disable Sticky keys prompt
# Write-Host "Disabling Sticky keys prompt..."
# Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "506"

# Enable Sticky keys prompt
# Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "510"

# Hide Search button / box
# Write-Host "Hiding Search Box / Button..."
# Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0

# Show Search button / box
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode"

# Hide Task View button
# Write-Host "Hiding Task View button..."
# Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0

# Show Task View button
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton"

# Show small icons in taskbar
# Write-Host "Showing small icons in taskbar..."
# Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Type DWord -Value 1

# Show large icons in taskbar
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons"

# Show titles in taskbar
# Write-Host "Showing titles in taskbar..."
# Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -Type DWord -Value 1

# Hide titles in taskbar
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel"

# Show all tray icons
Write-Host "Showing all tray icons..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Type DWord -Value 0

# Hide tray icons as needed
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray"

# Show known file extensions
Write-Host "Showing known file extensions..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0

# Hide known file extensions
# Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 1

# Show hidden files
# Write-Host "Showing hidden files..."
# Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1

# Hide hidden files
# Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 2

# Change default Explorer view to "Computer"
Write-Host "Changing default Explorer view to `"Computer`"..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1

# Change default Explorer view to "Quick Access"
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo"

# Show Computer shortcut on desktop
# Write-Host "Showing Computer shortcut on desktop..."
# If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu")) {
#	New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" | Out-Null
# }
# Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0
# Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0

# Hide Computer shortcut from desktop
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
# Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}"

# Remove Desktop icon from computer namespace
# Write-Host "Removing Desktop icon from computer namespace..."
# Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" -Recurse -ErrorAction SilentlyContinue

# Add Desktop icon to computer namespace
# New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}"

# Remove Documents icon from computer namespace
# Write-Host "Removing Documents icon from computer namespace..."
# Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}" -Recurse -ErrorAction SilentlyContinue
# Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}" -Recurse -ErrorAction SilentlyContinue

# Add Documents icon to computer namespace
# New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}"
# New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}"

# Remove Downloads icon from computer namespace
# Write-Host "Removing Downloads icon from computer namespace..."
# Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}" -Recurse -ErrorAction SilentlyContinue
# Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}" -Recurse -ErrorAction SilentlyContinue

# Add Downloads icon to computer namespace
# New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}"
# New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}"

# Remove Music icon from computer namespace
# Write-Host "Removing Music icon from computer namespace..."
# Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -Recurse -ErrorAction SilentlyContinue
# Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -Recurse -ErrorAction SilentlyContinue

# Add Music icon to computer namespace
# New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}"
# New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}"

# Remove Pictures icon from computer namespace
# Write-Host "Removing Pictures icon from computer namespace..."
# Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -Recurse -ErrorAction SilentlyContinue
# Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -Recurse -ErrorAction SilentlyContinue

# Add Pictures icon to computer namespace
# New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}"
# New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}"

# Remove Videos icon from computer namespace
# Write-Host "Removing Videos icon from computer namespace..."
# Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -Recurse -ErrorAction SilentlyContinue
# Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -Recurse -ErrorAction SilentlyContinue

# Add Videos icon to computer namespace
# New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}"
# New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}"

## Add secondary en-US keyboard
#Write-Host "Adding secondary en-US keyboard..."
#$langs = Get-WinUserLanguageList
#$langs.Add("en-US")
#Set-WinUserLanguageList $langs -Force

# Remove secondary en-US keyboard
# $langs = Get-WinUserLanguageList
# Set-WinUserLanguageList ($langs | ? {$_.LanguageTag -ne "en-US"}) -Force



##########
# Remove unwanted applications
##########

# Disable OneDrive
Write-Host "Disabling OneDrive..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive")) {
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1

# Enable OneDrive
# Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC"

# Uninstall OneDrive (WINDOWS WILL NOT SYSPREP WITHOUT IT!)
# Write-Host "Uninstalling OneDrive..."
# Stop-Process -Name OneDrive -ErrorAction SilentlyContinue
# Start-Sleep -s 3
# $onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
# If (!(Test-Path $onedrive)) {
# 	$onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
# }
# Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
# Start-Sleep -s 3
# Stop-Process -Name explorer -ErrorAction SilentlyContinue
# Start-Sleep -s 3
# Remove-Item "$env:USERPROFILE\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
# Remove-Item "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
# Remove-Item "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
# If (Test-Path "$env:SYSTEMDRIVE\OneDriveTemp") {
# 	Remove-Item "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse -ErrorAction SilentlyContinue
# }
# If (!(Test-Path "HKCR:")) {
# 	New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
# }
# Remove-Item -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
# Remove-Item -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue

# Install OneDrive
# $onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
# If (!(Test-Path $onedrive)) {
# 	$onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
# }
# Start-Process $onedrive -NoNewWindow

# Uninstall default Microsoft applications
Write-Host "Uninstalling default Microsoft applications..."
Get-AppxPackage "Microsoft.3DBuilder" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingFinance" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingNews" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingSports" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingWeather" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Getstarted" | Remove-AppxPackage
Get-AppxPackage "Microsoft.MicrosoftOfficeHub" | Remove-AppxPackage
Get-AppxPackage "Microsoft.MicrosoftSolitaireCollection" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Office.OneNote" | Remove-AppxPackage
Get-AppxPackage "Microsoft.People" | Remove-AppxPackage
Get-AppxPackage "Microsoft.SkypeApp" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Windows.Photos" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.WindowsAlarms" | Remove-AppxPackage
# Get-AppxPackage "Microsoft.WindowsCamera" | Remove-AppxPackage
Get-AppxPackage "microsoft.windowscommunicationsapps" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WindowsMaps" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WindowsPhone" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WindowsSoundRecorder" | Remove-AppxPackage
Get-AppxPackage "Microsoft.XboxApp" | Remove-AppxPackage
Get-AppxPackage "Microsoft.ZuneMusic" | Remove-AppxPackage
Get-AppxPackage "Microsoft.ZuneVideo" | Remove-AppxPackage
Get-AppxPackage "Microsoft.AppConnector" | Remove-AppxPackage
Get-AppxPackage "Microsoft.ConnectivityStore" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Office.Sway" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Messaging" | Remove-AppxPackage
Get-AppxPackage "Microsoft.CommsPhone" | Remove-AppxPackage
Get-AppxPackage "9E2F88E3.Twitter" | Remove-AppxPackage
Get-AppxPackage "king.com.CandyCrushSodaSaga" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WindowsFeedbackHub" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Wallet" | Remove-AppxPackage
Get-AppxPackage "Microsoft.ScreenSketch" | Remove-AppxPackage
Get-AppxPackage "Microsoft.GetHelp" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Xbox.TCUI" | Remove-AppxPackage
Get-AppxPackage "Microsoft.XboxGameOverlay" | Remove-AppxPackage
Get-AppxPackage "Microsoft.XboxSpeechToTextOverlay" | Remove-AppxPackage
Get-AppxPackage "Microsoft.MixedReality.Portal" | Remove-AppxPackage
Get-AppBackgroundTask "Microsoft.XboxIdentityProvider" | Remove-AppPackage


# Install default Microsoft applications
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.3DBuilder").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.BingFinance").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.BingNews").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.BingSports").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.BingWeather").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.Getstarted").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.MicrosoftOfficeHub").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.MicrosoftSolitaireCollection").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.Office.OneNote").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.People").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.SkypeApp").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.Windows.Photos").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.WindowsAlarms").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.WindowsCamera").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.windowscommunicationsapps").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.WindowsMaps").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.WindowsPhone").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.WindowsSoundRecorder").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.XboxApp").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.ZuneMusic").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.ZuneVideo").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.AppConnector").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.ConnectivityStore").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.Office.Sway").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.Messaging").InstallLocation)\AppXManifest.xml"
# Add-AppxPackage -DisableDevelopmentMode -Register "$($(Get-AppXPackage -AllUsers "Microsoft.CommsPhone").InstallLocation)\AppXManifest.xml"
# In case you have removed them for good, you can try to restore the files using installation medium as follows
# New-Item C:\Mnt -Type Directory | Out-Null
# dism /Mount-Image /ImageFile:D:\sources\install.wim /index:1 /ReadOnly /MountDir:C:\Mnt
# robocopy /S /SEC /R:0 "C:\Mnt\Program Files\WindowsApps" "C:\Program Files\WindowsApps"
# dism /Unmount-Image /Discard /MountDir:C:\Mnt
# Remove-Item -Path C:\Mnt -Recurse

# Uninstall Windows Media Player
# Write-Host "Uninstalling Windows Media Player..."
# dism /online /Disable-Feature /FeatureName:MediaPlayback /Quiet /NoRestart

# Install Windows Media Player
# dism /online /Enable-Feature /FeatureName:MediaPlayback /Quiet /NoRestart

# Uninstall Work Folders Client
Write-Host "Uninstalling Work Folders Client..."
dism /online /Disable-Feature /FeatureName:WorkFolders-Client /Quiet /NoRestart

# Install Work Folders Client
# dism /online /Enable-Feature /FeatureName:WorkFolders-Client /Quiet /NoRestart

# Set Photo Viewer as default for bmp, gif, jpg and png
Write-Host "Setting Photo Viewer as default for bmp, gif, jpg, png and tif..."
If (!(Test-Path "HKCR:")) {
	New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
}
ForEach ($type in @("Paint.Picture", "giffile", "jpegfile", "pngfile")) {
	New-Item -Path $("HKCR:\$type\shell\open") -Force | Out-Null
	New-Item -Path $("HKCR:\$type\shell\open\command") | Out-Null
	Set-ItemProperty -Path $("HKCR:\$type\shell\open") -Name "MuiVerb" -Type ExpandString -Value "@%ProgramFiles%\Windows Photo Viewer\photoviewer.dll,-3043"
	Set-ItemProperty -Path $("HKCR:\$type\shell\open\command") -Name "(Default)" -Type ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
}

# Remove or reset default open action for bmp, gif, jpg and png
# If (!(Test-Path "HKCR:")) {
# 	New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
# }
# Remove-Item -Path "HKCR:\Paint.Picture\shell\open" -Recurse
# Remove-ItemProperty -Path "HKCR:\giffile\shell\open" -Name "MuiVerb"
# Set-ItemProperty -Path "HKCR:\giffile\shell\open" -Name "CommandId" -Type String -Value "IE.File"
# Set-ItemProperty -Path "HKCR:\giffile\shell\open\command" -Name "(Default)" -Type String -Value "`"$env:SystemDrive\Program Files\Internet Explorer\iexplore.exe`" %1"
# Set-ItemProperty -Path "HKCR:\giffile\shell\open\command" -Name "DelegateExecute" -Type String -Value "{17FE9752-0B5A-4665-84CD-569794602F5C}"
# Remove-Item -Path "HKCR:\jpegfile\shell\open" -Recurse
# Remove-Item -Path "HKCR:\pngfile\shell\open" -Recurse

# Show Photo Viewer in "Open with..."
Write-Host "Showing Photo Viewer in `"Open with...`""
If (!(Test-Path "HKCR:")) {
	New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
}
New-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open\command" -Force | Out-Null
New-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open\DropTarget" -Force | Out-Null
Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open" -Name "MuiVerb" -Type String -Value "@photoviewer.dll,-3043"
Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open\command" -Name "(Default)" -Type ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open\DropTarget" -Name "Clsid" -Type String -Value "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}"

# Remove Photo Viewer from "Open with..."
# If (!(Test-Path "HKCR:")) {
# 	New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
# }
# Remove-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open" -Recurse

# This script disables unwanted Windows services. If you do not want to disable
# certain services comment out the corresponding lines below.

$services = @(
    "diagnosticshub.standardcollector.service" # Microsoft (R) Diagnostics Hub Standard Collector Service
    "DiagTrack"                                # Diagnostics Tracking Service
    "dmwappushservice"                         # WAP Push Message Routing Service (see known issues)
    "lfsvc"                                    # Geolocation Service
    "MapsBroker"                               # Downloaded Maps Manager
    "NetTcpPortSharing"                        # Net.Tcp Port Sharing Service
    "RemoteAccess"                             # Routing and Remote Access
    # "RemoteRegistry"                         # Remote Registry
    "SharedAccess"                             # Internet Connection Sharing (ICS)
    "TrkWks"                                   # Distributed Link Tracking Client
    # "WbioSrvc"                               # Windows Biometric Service (required for Fingerprint reader / facial detection)
    #"WlanSvc"                                 # WLAN AutoConfig
    "WMPNetworkSvc"                            # Windows Media Player Network Sharing Service
    #"wscsvc"                                  # Windows Security Center Service
    #"WSearch"                                 # Windows Search
    "XblAuthManager"                           # Xbox Live Auth Manager
    "XblGameSave"                              # Xbox Live Game Save Service
    "XboxNetApiSvc"                            # Xbox Live Networking Service
    "ndu"                                      # Windows Network Data Usage Monitor
    # Services which cannot be disabled
    #"WdNisSvc"
)

foreach ($service in $services) {
    Write-Output "Trying to disable $service"
    Get-Service -Name $service | Set-Service -StartupType Disabled
}


#   Description:
# This script optimizes Windows updates by disabling automatic download and
# seeding updates to other computers.
#
Import-Module -DisableNameChecking $PSScriptRoot\..\lib\New-FolderForced.psm1

Write-Output "Disable automatic download and installation of Windows updates"
New-FolderForced -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoUpdate" 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" "AUOptions" 2
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" "ScheduledInstallDay" 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" "ScheduledInstallTime" 3

Write-Output "Disable seeding of updates to other computers via Group Policies"
New-FolderForced -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" "DODownloadMode" 0

#echo "Disabling automatic driver update"
#sp "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" "SearchOrderConfig" 0

$objSID = New-Object System.Security.Principal.SecurityIdentifier "S-1-1-0"
$EveryOne = $objSID.Translate( [System.Security.Principal.NTAccount]).Value


Write-Output "Disable 'Updates are available' message"

takeown /F "$env:WinDIR\System32\MusNotification.exe"
icacls "$env:WinDIR\System32\MusNotification.exe" /deny "$($EveryOne):(X)"
takeown /F "$env:WinDIR\System32\MusNotificationUx.exe"
icacls "$env:WinDIR\System32\MusNotificationUx.exe" /deny "$($EveryOne):(X)"


# This script removes unwanted Apps that come with Windows. If you  do not want
# to remove certain Apps comment out the corresponding lines below.

Import-Module -DisableNameChecking $PSScriptRoot\..\lib\take-own.psm1
Import-Module -DisableNameChecking $PSScriptRoot\..\lib\New-FolderForced.psm1

Write-Output "Elevating privileges for this process"
do {} until (Elevate-Privileges SeTakeOwnershipPrivilege)

Write-Output "Uninstalling default apps"
$apps = @(
    # default Windows 10 apps
    "Microsoft.3DBuilder"
    "Microsoft.Advertising.Xaml"
    "Microsoft.Appconnector"
    "Microsoft.BingFinance"
    "Microsoft.BingNews"
    "Microsoft.BingSports"
    "Microsoft.BingTranslator"
    "Microsoft.BingWeather"
    #"Microsoft.FreshPaint"
    "Microsoft.GamingServices"
    "Microsoft.Microsoft3DViewer"
    "Microsoft.WindowsFeedbackHub"
    "Microsoft.MicrosoftOfficeHub"
    "Microsoft.MixedReality.Portal"
    "Microsoft.MicrosoftPowerBIForWindows"
    "Microsoft.MicrosoftSolitaireCollection"
    #"Microsoft.MicrosoftStickyNotes"
    "Microsoft.MinecraftUWP"
    "Microsoft.NetworkSpeedTest"
    "Microsoft.Office.OneNote"
    "Microsoft.People"
    "Microsoft.Print3D"
    "Microsoft.SkypeApp"
    "Microsoft.Wallet"
    # "Microsoft.Windows.Photos"
    # "Microsoft.WindowsAlarms"
    # "Microsoft.WindowsCalculator"
    # "Microsoft.WindowsCamera"
    "microsoft.windowscommunicationsapps"
    "Microsoft.WindowsMaps"
    "Microsoft.WindowsPhone"
    "Microsoft.WindowsSoundRecorder"
    #"Microsoft.WindowsStore"   # can't be re-installed
    "Microsoft.Xbox.TCUI"
    "Microsoft.XboxApp"
    "Microsoft.XboxGameOverlay"
    "Microsoft.XboxGamingOverlay"
    "Microsoft.XboxSpeechToTextOverlay"
    "Microsoft.YourPhone"
    "Microsoft.ZuneMusic"
    "Microsoft.ZuneVideo"
    "Microsoft.Windows.CloudExperienceHost"
    "Microsoft.Windows.ContentDeliveryManager"
    "Microsoft.Windows.PeopleExperienceHost"
    "Microsoft.XboxGameCallableUI"

    # Threshold 2 apps
    "Microsoft.CommsPhone"
    "Microsoft.ConnectivityStore"
    "Microsoft.GetHelp"
    "Microsoft.Getstarted"
    "Microsoft.Messaging"
    "Microsoft.Office.Sway"
    "Microsoft.OneConnect"
    "Microsoft.WindowsFeedbackHub"

    # Creators Update apps
    "Microsoft.Microsoft3DViewer"
    #"Microsoft.MSPaint"

    #Redstone apps
    "Microsoft.BingFoodAndDrink"
    "Microsoft.BingHealthAndFitness"
    "Microsoft.BingTravel"
    "Microsoft.WindowsReadingList"

    # Redstone 5 apps
    "Microsoft.MixedReality.Portal"
    "Microsoft.ScreenSketch"
    "Microsoft.XboxGamingOverlay"
    "Microsoft.YourPhone"

    # non-Microsoft
    "2FE3CB00.PicsArt-PhotoStudio"
    "46928bounde.EclipseManager"
    "4DF9E0F8.Netflix"
    "613EBCEA.PolarrPhotoEditorAcademicEdition"
    "6Wunderkinder.Wunderlist"
    "7EE7776C.LinkedInforWindows"
    "89006A2E.AutodeskSketchBook"
    "9E2F88E3.Twitter"
    "A278AB0D.DisneyMagicKingdoms"
    "A278AB0D.MarchofEmpires"
    "ActiproSoftwareLLC.562882FEEB491" # next one is for the Code Writer from Actipro Software LLC
    "CAF9E577.Plex"  
    "ClearChannelRadioDigital.iHeartRadio"
    "D52A8D61.FarmVille2CountryEscape"
    "D5EA27B7.Duolingo-LearnLanguagesforFree"
    "DB6EA5DB.CyberLinkMediaSuiteEssentials"
    "DolbyLaboratories.DolbyAccess"
    "DolbyLaboratories.DolbyAccess"
    "Drawboard.DrawboardPDF"
    "Facebook.Facebook"
    "Fitbit.FitbitCoach"
    "Flipboard.Flipboard"
    "GAMELOFTSA.Asphalt8Airborne"
    "KeeperSecurityInc.Keeper"
    "NORDCURRENT.COOKINGFEVER"
    "PandoraMediaInc.29680B314EFC2"
    "Playtika.CaesarsSlotsFreeCasino"
    "ShazamEntertainmentLtd.Shazam"
    "SlingTVLLC.SlingTV"
    "SpotifyAB.SpotifyMusic"
    #"TheNewYorkTimes.NYTCrossword"
    "ThumbmunkeysLtd.PhototasticCollage"
    "TuneIn.TuneInRadio"
    "WinZipComputing.WinZipUniversal"
    "XINGAG.XING"
    "flaregamesGmbH.RoyalRevolt2"
    "king.com.*"
    "king.com.BubbleWitch3Saga"
    "king.com.CandyCrushSaga"
    "king.com.CandyCrushSodaSaga"

    # apps which cannot be removed using Remove-AppxPackage
    #"Microsoft.BioEnrollment"
    #"Microsoft.MicrosoftEdge"
    #"Microsoft.Windows.Cortana"
    #"Microsoft.WindowsFeedback"
    #"Microsoft.XboxGameCallableUI"
    #"Microsoft.XboxIdentityProvider"
    #"Windows.ContactSupport"

    # apps which other apps depend on
    "Microsoft.Advertising.Xaml"
)

foreach ($app in $apps) {
    Write-Output "Trying to remove $app"

    Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -AllUsers

    Get-AppXProvisionedPackage -Online |
        Where-Object DisplayName -EQ $app |
        Remove-AppxProvisionedPackage -Online
}

# Prevents Apps from re-installing
$cdm = @(
    "ContentDeliveryAllowed"
    "FeatureManagementEnabled"
    "OemPreInstalledAppsEnabled"
    "PreInstalledAppsEnabled"
    "PreInstalledAppsEverEnabled"
    "SilentInstalledAppsEnabled"
    "SubscribedContent-314559Enabled"
    "SubscribedContent-338387Enabled"
    "SubscribedContent-338388Enabled"
    "SubscribedContent-338389Enabled"
    "SubscribedContent-338393Enabled"
    "SubscribedContentEnabled"
    "SystemPaneSuggestionsEnabled"
)

New-FolderForced -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
foreach ($key in $cdm) {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" $key 0
}

New-FolderForced -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" "AutoDownload" 2

# Prevents "Suggested Applications" returning
New-FolderForced -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" 1

#   Description:
# This script will remove and disable OneDrive integration.

Import-Module -DisableNameChecking $PSScriptRoot\..\lib\New-FolderForced.psm1
Import-Module -DisableNameChecking $PSScriptRoot\..\lib\take-own.psm1

Write-Output "Kill OneDrive process"
taskkill.exe /F /IM "OneDrive.exe"
taskkill.exe /F /IM "explorer.exe"

Write-Output "Remove OneDrive"
if (Test-Path "$env:systemroot\System32\OneDriveSetup.exe") {
    & "$env:systemroot\System32\OneDriveSetup.exe" /uninstall
}
if (Test-Path "$env:systemroot\SysWOW64\OneDriveSetup.exe") {
    & "$env:systemroot\SysWOW64\OneDriveSetup.exe" /uninstall
}

Write-Output "Removing OneDrive leftovers"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:localappdata\Microsoft\OneDrive"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:programdata\Microsoft OneDrive"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:systemdrive\OneDriveTemp"
# check if directory is empty before removing:
If ((Get-ChildItem "$env:userprofile\OneDrive" -Recurse | Measure-Object).Count -eq 0) {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:userprofile\OneDrive"
}

Write-Output "Disable OneDrive via Group Policies"
New-FolderForced -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive" "DisableFileSyncNGSC" 1

Write-Output "Remove Onedrive from explorer sidebar"
New-PSDrive -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" -Name "HKCR"
mkdir -Force "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
Set-ItemProperty -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
mkdir -Force "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
Set-ItemProperty -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
Remove-PSDrive "HKCR"

# Thank you Matthew Israelsson
Write-Output "Removing run hook for new users"
reg load "hku\Default" "C:\Users\Default\NTUSER.DAT"
reg delete "HKEY_USERS\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f
reg unload "hku\Default"

Write-Output "Removing startmenu entry"
Remove-Item -Force -ErrorAction SilentlyContinue "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk"

Write-Output "Removing scheduled task"
Get-ScheduledTask -TaskPath '\' -TaskName 'OneDrive*' -ea SilentlyContinue | Unregister-ScheduledTask -Confirm:$false

Write-Output "Restarting explorer"
Start-Process "explorer.exe"

Write-Output "Waiting for explorer to complete loading"
Start-Sleep 10

Write-Output "Removing additional OneDrive leftovers"
foreach ($item in (Get-ChildItem "$env:WinDir\WinSxS\*onedrive*")) {
    Takeown-Folder $item.FullName
    Remove-Item -Recurse -Force $item.FullName
}



# Remove Password Age Limit (Passwords never expire) #

net accounts /maxpwage:0


# Set Password Age Limit to 60 Days#

#net accounts /maxpwage:60


# This script removes all Start Menu Tiles from the .default user #

Set-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -Value '<LayoutModificationTemplate xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" Version="1" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '  <LayoutOptions StartTileGroupCellWidth="6" />'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '  <DefaultLayoutOverride>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '    <StartLayoutCollection>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '      <defaultlayout:StartLayout GroupCellWidth="6" />'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '    </StartLayoutCollection>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '  </DefaultLayoutOverride>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '    <CustomTaskbarLayoutCollection>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '      <defaultlayout:TaskbarLayout>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '        <taskbar:TaskbarPinList>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '          <taskbar:UWA AppUserModelID="Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge" />'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '          <taskbar:DesktopApp DesktopApplicationLinkPath="%APPDATA%\Microsoft\Windows\Start Menu\Programs\System Tools\File Explorer.lnk" />'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '        </taskbar:TaskbarPinList>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '      </defaultlayout:TaskbarLayout>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '    </CustomTaskbarLayoutCollection>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '</LayoutModificationTemplate>'

$START_MENU_LAYOUT = @"
<LayoutModificationTemplate xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" Version="1" xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">
    <LayoutOptions StartTileGroupCellWidth="6" />
    <DefaultLayoutOverride>
        <StartLayoutCollection>
            <defaultlayout:StartLayout GroupCellWidth="6" />
        </StartLayoutCollection>
    </DefaultLayoutOverride>
</LayoutModificationTemplate>
"@

$layoutFile="C:\Windows\StartMenuLayout.xml"

#Delete layout file if it already exists
If(Test-Path $layoutFile)
{
    Remove-Item $layoutFile
}

#Creates the blank layout file
$START_MENU_LAYOUT | Out-File $layoutFile -Encoding ASCII

$regAliases = @("HKLM", "HKCU")

#Assign the start layout and force it to apply with "LockedStartLayout" at both the machine and user level
foreach ($regAlias in $regAliases){
    $basePath = $regAlias + ":\SOFTWARE\Policies\Microsoft\Windows"
    $keyPath = $basePath + "\Explorer" 
    IF(!(Test-Path -Path $keyPath)) { 
        New-Item -Path $basePath -Name "Explorer"
    }
    Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 1
    Set-ItemProperty -Path $keyPath -Name "StartLayoutFile" -Value $layoutFile
}

#Restart Explorer, open the start menu (necessary to load the new layout), and give it a few seconds to process
Stop-Process -name explorer
Start-Sleep -s 5
$wshell = New-Object -ComObject wscript.shell; $wshell.SendKeys('^{ESCAPE}')
Start-Sleep -s 5

#Enable the ability to pin items again by disabling "LockedStartLayout"
foreach ($regAlias in $regAliases){
    $basePath = $regAlias + ":\SOFTWARE\Policies\Microsoft\Windows"
    $keyPath = $basePath + "\Explorer" 
    Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 0
}

#Restart Explorer and delete the layout file
Stop-Process -name explorer

# Uncomment the next line to make clean start menu default for all new users
Import-StartLayout -LayoutPath $layoutFile -MountPath $env:SystemDrive\

Remove-Item $layoutFile


# Prevents SYSPREP from freezing at "Getting Ready" on first boot                          #
# NOTE, DMWAPPUSHSERVICE is a Keyboard and Ink telemetry service, and potential keylogger. #
# It is recommended to disable this service in new builds, but SYSPREP will freeze/fail    #
# if the service is not running. If SYSPREP will be used, add a FirstBootCommand to your   #
# build to disable the service.                                                            #

reg delete "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\dmwappushservice" /v "DelayedAutoStart" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\dmwappushservice" /v "DelayedAutoStart" /t REG_DWORD /d "1"
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\dmwappushservice" /v "Start" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "2"
# Add the line below to FirstBootCommand in answer file #
# reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v "disabledmwappushservice" /t REG_SZ /d "sc config dmwappushservice start= disabled"


# Disable Privacy Settings Experience #
# Also disables all settings in Privacy Experience #

reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OOBE" /v "DisablePrivacyExperience" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OOBE" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OOBE" /v "DisablePrivacyExperience" /t REG_DWORD /d "1" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Speech_OneCore" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Speech_OneCore\Settings" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t REG_DWORD /d "0" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Speech_OneCore" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Speech_OneCore\Settings" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t REG_DWORD /d "0" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Settings\FindMyDevice" /v "LocationSyncEnabled" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Settings\FindMyDevice" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Settings\FindMyDevice" /v "LocationSyncEnabled" /t REG_DWORD /d "0" /f
reg delete "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /t REG_DWORD /d "1" /f
reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /t REG_DWORD /d "1" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "1" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "MaxTelemetryAllowed" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "MaxTelemetryAllowed" /t REG_DWORD /d "1" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Input\TIPC" /v "Enabled" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Input" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Input\TIPC" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d "0" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Input\TIPC" /v "Enabled" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Input" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Input\TIPC" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d "0" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Privacy" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Privacy" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f


# Set Windows to Dark Mode #

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /v "AppsUseLightTheme" /t "REG_DWORD" /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /v "SystemUsesLightTheme" /t "REG_DWORD" /d "0" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t "REG_DWORD" /d "0" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t "REG_DWORD" /d "0" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t "REG_DWORD" /d "0" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t "REG_DWORD" /d "0" /f

##########
# Restart
##########
Write-Host
Write-Host "Press any key to restart your system..." -ForegroundColor Black -BackgroundColor White
$key = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
Write-Host "Restarting..."
Restart-Computer