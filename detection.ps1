<#
IFT380 Mod4  - NOCorps Lab 2 
Detection Rev-2
#> 

$prived =  icacls $env:windir\system32\config\sam 
$listem = vssadmin list shadows | Out-String

if ($prived -like "*Everyone|BUILTIN\Users*" -or $listem -like "*Contents of shadow copy*") {
    # We have access, system is vulnerable...probably actually a failure
    return "Success"
}  
else {
    # We dont have access, system isnt vulnerable
    return "Failure"
}






