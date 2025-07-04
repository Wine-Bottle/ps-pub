# KB: https://techcommunity.microsoft.com/blog/windows-itpro-blog/act-now-secure-boot-certificates-expire-in-june-2026/4426856
# Detect-SecureBootDBCAcert.ps1
$SecureBootUpdateStatus = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).bytes) -match 'Windows UEFI CA 2023'
if ($SecureBootUpdateStatus) {
   Write-Output "SecureBootUEFI DB already up to date"
   $exitcode = "0"
} else {
   Write-Output "SecureBootUEFI DB is not up to date"
   $remediate = "1"
}
# Detect-SecureBoot.ps1
$SecureBoot = Confirm-SecureBootUEFI
if ($SecureBoot) {
   Write-Output "SecureBoot confirmed enabled"
   $remediate += "0"
} else {
   Write-Output "SecureBoot confirmed not enabled"
   $remediate += "10"
}
# Detect-BootMgrCert.ps1
# Mount EFI partition as "S:"
try {
   Write-Output "Attempting to mount EFI partition as S:"
   mountvol s: /s
} catch {
   Write-Output "Cannot mount EFI partition, you know what's wrong :) and what to do :)"
   $remediate += "100"
}
# Check EFI parition availability
$EFIpartition = Test-Path "S:"
if ($EFIPartiion) {
   # Get boot manager signer certificate
   $BootMgrSignerCert = (Get-AuthenticodeSignature S:\EFI\Microsoft\Boot\bootmgfw.efi).SignerCertificate
   if ($BootMgrSignerCert.Issuer -Match "Windows UEFI CA 2023") {
      Write-Output "Boot manager already signed with `"Windows UEFI CA 2023`""
      $remeidate+="0"
   } elseif ($BootMgrSignerCert.Issuer -Match "Windows Production PCA 2011") {
      Write-Output "Boot manager already signed with `"Windows Production PCA 2011`", vulnerable and requires update (0x100)"
      $remediate+="1000"
   } else {
      Write-Output "Boot manager signed with unknown certificate, I guess you are reading from the future, don't know why you are reading this script"
      $remediate+="0"
   }
}
# Final output
Write-Output "# 1000 (Old Boot mgr), 100 (MBR / no separate EFI partition), 10 (SecureBoot not enabled), 1 (SecureBootUEFI DB unpatched)"
Write-Output "Status code: $remediate"
if ($remediate -eq "0") {
   Exit 0 # Remediation not required
} else {
   Exit 1 # Remediation required
}
