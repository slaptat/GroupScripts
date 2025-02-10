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

# Remove vulnerable permissions from SAM file
icacls $env:windir\system32\config\sam /remove:g Everyone
icacls $env:windir\system32\config\sam /remove:g "BUILTIN\Users"

# Restrict access to the entire config folder
icacls $env:windir\system32\config /remove:g Everyone
icacls $env:windir\system32\config /remove:g "BUILTIN\Users"

# Restore correct inheritance for SAM and config folder
icacls $env:windir\system32\config\sam /inheritance:e
icacls $env:windir\system32\config /inheritance:e
    