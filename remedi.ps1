<#
IFT380 Mod4  - NOCorps Lab 2 
Remediation
#>

$listEm = vssadmin list shadows # List shadows

if ($listEm) {
    vssadmin delete shadows /for=%systemdrive% /Quiet
    Return "Deleted"
}
else {
    Return "Fail"
}

icacls $env:windir\system32\config\*.* /inheritance:e
    