<#
IFT380 Mod4  - NOCorps Lab 2 
Detection
#>

$prived =  icacls $env:windir\system32\config\sam 

if ($prived -like "*Everyone|BUILTIN\Users*") {
    # We have access, system is vulnerable...probably actually a failure
    return "Success"
}  
else {
    # We dont have access, system isnt vulnerable
    return "Failure"
}






