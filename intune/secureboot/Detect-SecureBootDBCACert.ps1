# KB: https://techcommunity.microsoft.com/blog/windows-itpro-blog/act-now-secure-boot-certificates-expire-in-june-2026/4426856
# Detect-SecureBootDBCAcert.ps1
$SecureBootUpdateStatus = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).bytes) -match 'Windows UEFI CA 2023'
if ($SecureBootUpdateStatus) {
   Exit 0 # Remediation not required
} else {
   Exit 1 # Remediation required
}