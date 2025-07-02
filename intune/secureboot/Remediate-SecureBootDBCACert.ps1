# Remediate-SecureBootDBCAcert.ps1
# String parse securebootuefi DB to check for required certificate
$SecureBootUpdateStatus = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).bytes) -match 'Windows UEFI CA 2023'
if ($SecureBootUpdateStatus) {
   Write-Output "Remediation not required"
   # Cert exists, remediation not required
} else {
   # Cert doesn't exist, remediation required
   # Check patch level, require cumulative patches >2024/02
   $PatchLevelVerification = (Get-HotFix | select -Last 1).InstalledOn -gt "2024/02/01"
   if ($PatchLevelVerification) {
      Write-Output "System patch level >2024/02, proceeding with SecureBoot DB update"
      # Checks if SecureBoot update registry is primed (accepting updates)
      $secureBootAvailableUpdates = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot")."AvailableUpdates"
      if ($secureBootAvailableUpdates -eq "0") {
         Write-Output "If SecureBoot update registry is not accepting updates, update value to accept update"
         Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" -Name "AvailableUpdates" -Value 0x40
      }
      Write-Output "Run built-in scheduled task to update SecureBoot DB"
      Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
      # BitLocker status checks
      $OSDriveBitLockerStatus = Get-BitLockerVolume | ? VolumeType -eq "OperatingSystem"
      if ($OSDriveBitLockerStatus.ProtectionStatus -eq "On") {
         Write-Output "OS drive is protected with BitLocker, suspending for 2 reboots for SecureBoot DB cert to be updated and apply"
         Start-Process "Manage-bde.exe" -ArgumentList "-Protectors -Disable $env:SystemDrive -RebootCount 2"
      } else {
         $ProtectionStatus = $OSDriveBitLockerStatus.ProtectionStatus
         Write-Output "OS drive protection status is not `"On`", will not suspend BitLocker"
         Write-Output "OS drive protection status: $ProtectionStatus"
      }
   } else {
   Write-Output "Patch system first, require patches > 2024/02"
   }
}