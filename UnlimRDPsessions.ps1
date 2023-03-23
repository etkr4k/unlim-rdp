###################################################################
#
#
# Script work with following versions of windows:
#
#
# Windows 11 RTM 21H2	39 81 3C 06 00 00 0F 84 4F 68 01 00
# Windows 10 x64 21H2	39 81 3C 06 00 00 0F 84 DB 61 01 00
# Windows 10 x64 21H1	39 81 3C 06 00 00 0F 84 2B 5F 01 00
# Windows 10 x64 20H2	39 81 3C 06 00 00 0F 84 21 68 01 00
# Windows 10 x64 2004	39 81 3C 06 00 00 0F 84 D9 51 01 00
# Windows 10 x64 1909	39 81 3C 06 00 00 0F 84 5D 61 01 00
# Windows 10 x64 1903	39 81 3C 06 00 00 0F 84 5D 61 01 00
# Windows 10 x64 1809	39 81 3C 06 00 00 0F 84 3B 2B 01 00
# Windows 10 x64 1803	8B 99 3C 06 00 00 8B B9 38 06 00 00
# Windows 10 x64 1709	39 81 3C 06 00 00 0F 84 B1 7D 02 00
#
# Replace with			B8 00 01 00 00 89 81 38 06 00 00 90
#
#
###################################################################
Function StopRDPservice {
 If (($Service1PID -eq 0) -and ($Service2PID -eq 0)) {
  Write-Output ' Services are not running. Disabling...'
  Set-Service -Name UmRdpService -StartupType Disabled
  Set-Service -Name TermService -StartupType Disabled
 }
 Elseif (($Service1PID -ne 0) -and ($Service2PID -ne 0)) {
  Write-Output ' Services are running. Disabling and stopping...'
  Set-Service -Name UmRdpService -StartupType Disabled
  Set-Service -Name TermService -StartupType Disabled
  Stop-Process -ID $Service1PID -Force
  Stop-Process -ID $Service2PID -Force
 }
 Elseif (($Service1PID -ne 0) -and ($Service2PID -eq 0)) {
  Write-Output ' Strange but only UmRdpService is running :| . Disabling and stopping...'
  Set-Service -Name UmRdpService -StartupType Disabled
  Set-Service -Name TermService -StartupType Disabled
  Stop-Process -ID $Service1PID -Force
 }
 Elseif (($Service1PID -eq 0) -and ($Service2PID -ne 0)) {
  Write-Output ' Strange but only TermService is running :| . Disabling and stopping...'
  Set-Service -Name UmRdpService -StartupType Disabled
  Set-Service -Name TermService -StartupType Disabled
  Stop-Process -ID $Service2PID -Force
 }
 else {
  Write-Output ' Something went wrong :( . Exiting...' ''
  Break
 }
}
Function RestoreRDPservice {
 If (($Service1PID -eq 0) -and ($Service2PID -eq 0)) {
  Set-Service -Name UmRdpService -StartupType $Service1OrigST
  Set-Service -Name TermService -StartupType $Service2OrigST
 }
 Elseif (($Service1PID -ne 0) -and ($Service2PID -ne 0)) {
  Set-Service -Name UmRdpService -StartupType $Service1OrigST
  Set-Service -Name TermService -StartupType $Service2OrigST
  Start-Service UmRdpService
  Start-Service TermService
 }
 Elseif (($Service1PID -ne 0) -and ($Service2PID -eq 0)) {
  Set-Service -Name UmRdpService -StartupType $Service1OrigST
  Set-Service -Name TermService -StartupType $Service2OrigST
  Start-Service UmRdpService
 }
 Elseif (($Service1PID -eq 0) -and ($Service2PID -ne 0)) {
  Set-Service -Name UmRdpService -StartupType $Service1OrigST
  Set-Service -Name TermService -StartupType $Service2OrigST
  Start-Service TermService
 }
 else {
  Write-Output ' Something went wrong :( , exiting...' ''
  Break
 }
}
Function ChangeACL {
 takeown /f C:\Windows\System32\termsrv.dll
 takeown /f C:\Windows\System32\termsrv.dll.orig
 $NewOwner = (Get-Acl C:\Windows\System32\termsrv.dll).owner
 Write-Output ''
 cmd /c "icacls %windir%\System32\termsrv.dll /Grant $($NewOwner):F /C"
 Write-Output ''
 cmd /c "icacls %windir%\System32\termsrv.dll.orig /Grant $($NewOwner):F /C"
}
Clear-Host
Write-Output '' ' ### Unlimited RDP Sessions ###' '' ' Checking Windows version and permissions...' ''
if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 10000) {
 if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
  Write-Output ' Not running as administrator :( . Exiting...' ''
  Break
 }
}
else {
 Write-Output ' Windows version is less than 10.0 :( . Exiting...' ''
 Break
}
Write-Output ' Everything is OK :) . Checking termsrv.dll file...' ''
$DLLasBytes = Get-Content C:\Windows\System32\termsrv.dll -Raw -Encoding byte
$DLLasText = $DLLasBytes.forEach('ToString', 'X2') -join ' '
$PatternW10 = ([regex]'39 81 3C 06 00 00 0F 84(\s\S\S){4}')
$PatternW10_1803 = '8B 99 3C 06 00 00 8B B9 38 06 00 00'
$PatchW10 = 'B8 00 01 00 00 89 81 38 06 00 00 90'
If (Select-String -Pattern $PatternW10 -InputObject $DLLasText) {
 Write-Output ' Pattern found. Preparing variables...'
 $DLLasTextReplaced = $DLLasText -replace $PatternW10, $PatchW10
}
Elseif (Select-String -Pattern $PatternW10_1803 -InputObject $DLLasText) {
 Write-Output ' Pattern found. Preparing variables...'
 $DLLasTextReplaced = $DLLasText -replace $PatternW10_1803, $PatchW10
}
Elseif (Select-String -Pattern $PatchW10 -InputObject $DLLasText) {
 Write-Output ' The termsrv.dll file is already patched.' ''
 $confirmation = Read-Host " Do you want to restore original file? (y/n)"
 Write-Output ''
 if ($confirmation -eq 'y') {
  if (Test-Path -Path C:\Windows\system32\termsrv.dll.orig -PathType Leaf) {
   Write-Output ' Restoring original termsrv.dll...' '' ' Checking is UmRdpService and TermService services running...' ''
   $Service1OrigST = Get-Service UmRdpService | Select-Object -ExpandProperty StartType
   $Service2OrigST = Get-Service TermService | Select-Object -ExpandProperty StartType
   $Service1PID = Get-WmiObject -Class Win32_Service -Filter "Name LIKE 'UmRdpService'" | Select-Object -ExpandProperty ProcessId
   $Service2PID = Get-WmiObject -Class Win32_Service -Filter "Name LIKE 'TermService'" | Select-Object -ExpandProperty ProcessId
   StopRDPservice
   Write-Output '' ' Done. Replacing ACLs for termsrv.dll...'
   $OrigACL = Get-Acl C:\Windows\System32\termsrv.dll
   ChangeACL
   Write-Output '' ' Replacing ACLs completed. Restoring file...'
   Copy-Item C:\Windows\system32\termsrv.dll C:\Windows\system32\termsrv.dll.patched -Force
   Copy-Item C:\Windows\System32\termsrv.dll.orig C:\Windows\System32\termsrv.dll -Force
   Write-Output '' ' termsrv.dll restored. Removing temp files...'
   Remove-Item -Path C:\Windows\system32\termsrv.dll.orig -Force
   Remove-Item -Path C:\Windows\system32\termsrv.dll.patched -Force
   Write-Output '' ' Temp files removed. Restoring ACL...'
   Set-Acl C:\Windows\system32\termsrv.dll $OrigACL
   Write-Output '' ' Restoring ACL completed. Current owner:' '' (Get-Acl C:\Windows\System32\termsrv.dll).owner '' ' Restoring services states...' ''
   RestoreRDPservice
   Write-Output ' Service states restored.' '' ' All done!' ''
   Break
  }
  else {
   Write-Output ' File termsrv.dll.orig not found :( . Exiting...' ''
   Break
  }
 }
 elseif ($confirmation -eq 'n') {
  Write-Output ' Okay. Exiting...' ''
  Break
 }
 else {
  Write-Output ' whatever :/ . Exiting...' ''
  Break
 }
}
else {
 Write-Output ' Pattern not found :( . Exiting...' ''
 Break
}
Write-Output '' ' Variables prepeared.' ''
$confirmation = Read-Host " Are you sure you want to patch termsrv.dll file? (y/n)"
if ($confirmation -eq 'y') {
 Write-Output '' ' Confirmed. Checking is UmRdpService and TermService services running...' ''
}
elseif ($confirmation -eq 'n') {
 Write-Output '' ' Okay. Exiting...' ''
 Break
}
else {
 Write-Output '' ' whatever :/ . Exiting...' ''
 Break
}
$Service1OrigST = Get-Service UmRdpService | Select-Object -ExpandProperty StartType
$Service2OrigST = Get-Service TermService | Select-Object -ExpandProperty StartType
$Service1PID = Get-WmiObject -Class Win32_Service -Filter "Name LIKE 'UmRdpService'" | Select-Object -ExpandProperty ProcessId
$Service2PID = Get-WmiObject -Class Win32_Service -Filter "Name LIKE 'TermService'" | Select-Object -ExpandProperty ProcessId
StopRDPservice
Write-Output '' ' Done. Creating backup of termsrv.dll...' ''
Copy-Item C:\Windows\System32\termsrv.dll C:\Windows\System32\termsrv.dll.orig
Write-Output ' Backup created (C:\Windows\System32\termsrv.dll.orig)' '' ' Replacing ACLs for termsrv.dll...'
$OrigACL = Get-Acl C:\Windows\System32\termsrv.dll
ChangeACL
Write-Output '' ' Replacing ACLs completed. Creating patched termsrv.dll file...'
[byte[]] $DLLasBytesReplaced = -split $DLLasTextReplaced -replace '^', '0x'
Set-Content C:\Windows\System32\termsrv.dll.patched -Encoding Byte -Value $DLLasBytesReplaced
Write-Output '' ' File created. Comparing files...' ''
fc.exe /b C:\Windows\system32\termsrv.dll.patched C:\Windows\system32\termsrv.dll
Write-Output '' ' Replacing termsrv.dll file...' ''
Copy-Item C:\Windows\system32\termsrv.dll.patched C:\Windows\system32\termsrv.dll -Force
Write-Output ' termsrv.dll replaced. Removing temp files...' ''
Remove-Item -Path C:\Windows\system32\termsrv.dll.patched -Force
Write-Output ' Temp files removed. Restoring ACL...' ''
Set-Acl C:\Windows\system32\termsrv.dll $OrigACL
Set-Acl C:\Windows\system32\termsrv.dll.orig $OrigACL
Write-Output ' Restoring ACL completed. Current owner:' '' (Get-Acl C:\Windows\System32\termsrv.dll).owner '' ' Restoring ACL completed. Restoring services states...' ''
RestoreRDPservice
Write-Output ' Restoring services states completed.' '' ' All done!' '' ' Original termsrv.dll located at C:\Windows\System32\termsrv.dll.orig' ''
Break
