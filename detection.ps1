<#
IFT380 Mod4  - NOCorps Lab 2 
Well start by detecting for HiveNightmare, then remediation
#>


$prived =  icacls $env:windir\system32\config\sam 
$listEm = vssadmin list shadows # List shadows

function sleepy {  
    param (
        [string]$time = 1
    )
        Start-Sleep -Seconds $time
}

    <# 
-Check if system is vulnerable -

This kind of works, but kind of dont. First im not sure we can gaurantee its checking with correct privs, but assuming it does I still need to verify that it returns correctly as it seems to hand a true return when the command is broken. Maybe its not important in the scope of the assignment though. But for now it works on my system how it sits.
#>
Write-Host "`nChecking if client is vulnerable..." -ForegroundColor Green
sleepy
if ($LASTEXITCODE -eq 0) {
    @{
        Success = $true
        Permissions = $prived 
        Message = "Successfully retrieved permissions"
    }
    
    Write-Host "`n*** System is Vulnerable..." -ForegroundColor Yellow
    Write-Host "*** Attempting to restict access...`n" -ForegroundColor Yellow
    sleepy -time 2
    try {
        Start-Process -Filepath calc.exe 
        #icacls $env:windir\system32\config\*.* /inheritance:e
        Write-Host "*** Successfuly secured the system! Were really hacking now." -ForegroundColor Green
    }
    catch {
        Write-Host "*** Failed to secure access!!: " -ForegroundColor Red
        Write-Host "    `"$_`" " -ForegroundColor DarkMagenta
    }
}
elseif ($LASTEXITCODE -eq 1) {
    @{
        Success = $false
        Message = "Failed retrieving permissions"
    }
}


if ($listEm) {
    Write-Host "`n`n*** Shadow found!" -ForegroundColor Yellow
    try {
        Write-Host "*** Deleting Shadow...`n" -ForegroundColor Yellow
        #vssadmin delete shadows /for=%systemdrive% /Quiet
        sleepy -time 1
        Write-Host "`n`n*** Success!`n" -ForegroundColor Green
    }
    catch {
        Write-Host "Deletion Failed`n" -ForegroundColor Red
    }
}
else {
    Write-Host "Relax, no shadows found...Moving on`n" -ForegroundColor Green
}


