# KB: https://support.microsoft.com/en-us/topic/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d
# Remediate-SecureBootDBCAcert.ps1
# String parse securebootuefi DB to check for required certificate
$SecureBootUpdateStatus = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).bytes) -match 'Windows UEFI CA 2023'
if ($SecureBootUpdateStatus) {
   Write-Output "SecureBootUEFI DB up-to-date"
} else {
   # Cert using "Windows Production PCA 2011", remediation required
   # Check patch level, require cumulative patches >2024/02
   $PatchLevelVerification = (Get-HotFix | select -Last 1).InstalledOn -gt "2024/02/01"
   if ($PatchLevelVerification) {
      Write-Output "System patch level >2024/02, proceeding with SecureBoot DB update"
      Write-Output "Set SecureBoot update registry to accept SecureBoot DB update (0x40)"
      Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" -Name "AvailableUpdates" -Value 0x40
      Write-Output "Run built-in scheduled task to update SecureBoot DB"
      Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
      #
      Write-Output "Set reboot pending and toast noti"
      $reboot = $true
   } else {
   Write-Output "Patch system first, require patches > 2024/02"
   }
}
# 
# Remediate-BootMgrCert.ps1
# Mount EFI partition as "S:"
# Check if pending reboot from previous section, if pending reboot, requires second script run to patch EFI signer cert
if ($reboot -eq $null) {
   Write-Output "Attempting to mount EFI partition as S:"
   mountvol s: /s
   # Check EFI parition availability
   $EFIpartition = Test-Path "S:"
   if ($EFIPartiion) {
      # Get boot manager signer certificate
      $BootMgrSignerCert = (Get-AuthenticodeSignature S:\EFI\Microsoft\Boot\bootmgfw.efi).SignerCertificate
      if ($BootMgrSignerCert.Issuer -Match "Windows Production PCA 2011") {
         Write-Output "Boot manager signed with `"Windows Production PCA 2011`", boot manager is vulnerable and requires update (0x100)"
         Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" -Name "AvailableUpdates" -Value 0x100
         Write-Output "Run built-in scheduled task to update EFI boot manager signer cert"
         Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
         #
         Write-Output "Set reboot pending and toast noti"
         $reboot = $true
      } else {
         Write-Output "Boot manager signed with non vulnerable certificate, no further actions"
      }
   }
}
# Reboot flag -> Reboot + reboot noti
if ($reboot) {
   New-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" | Out-Null
   New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -Name "UpdatePending" -Value "1" -PropertyType "DWord" -Force | Out-Null
   New-ItemProperty "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\Orchestrator" | Out-Null
   New-ItemProperty "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\Orchestrator" -Name "ShutdownFlyoutOptions" -Value "10" -PropertyType "DWord" -Force | Out-Null
   New-ItemProperty "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\Orchestrator" -Name "EnhancedShutdownEnabled" -Value "1" -PropertyType "DWord" -Force | Out-Null
   # BitLocker OS drive status checks -> Suspend twice
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
   # Logic: reboot not required, but detect script still triggers. Hints below.
   $SecureBoot = Confirm-SecureBootUEFI
   Write-Output "Is secureboot even enabled? SecureBoot status: $SecureBoot"
   # KB: https://www.techepages.com/how-to-find-tpm-version-of-a-computer-using-powershell/
   $tpm = gcim Win32_Tpm -namespace "root\CIMV2\Security\MicrosoftTpm"
   Write-Output "TPM activated: $($tpm.IsActivated_InitialValue); Enabled: $($tpm.IsEnabled_InitialValue); Spec: $($tpm.SpecVersion.split(",")[0])"
   # KB: https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity
   $DeviceGuard = gcim Win32_DeviceGuard -Namespace "root\Microsoft\Windows\DeviceGuard"
   Write-Output "VBS (1-enabled, not running; 2-enabled, running): $($DeviceGuard.VirtualizationBasedSecurityStatus)"
}