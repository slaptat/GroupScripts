<#
IFT380 Mod4  - NOCorps Lab 2 
We'll start by detecting HiveNightmare.
#>

$prived = icacls $env:windir\system32\config\sam
$listEm = vssadmin list shadows # List shadow copies

function sleepy {  
    param (
        [string]$time = 1
    )
    Start-Sleep -Seconds $time
}

<# 
-Check if system is vulnerable -
#>
Write-Host "`nChecking if client is vulnerable..." -ForegroundColor Green
sleepy

$Vulnerable = $prived -like "*Everyone|BUILTIN\Users*"

if ($Vulnerable) {
    @{
        Success = $true
        Permissions = $prived 
        Message = "Successfully retrieved permissions"
    }

    Write-Host "`n*** System is Vulnerable..." -ForegroundColor Yellow
    Write-Host "*** Attempting to restrict access...`n" -ForegroundColor Yellow
    sleepy -time 2

    try {
        # Remove vulnerable permissions from SAM file
        icacls $env:windir\system32\config\sam /remove:g Everyone
        icacls $env:windir\system32\config\sam /remove:g "BUILTIN\Users"

        # Restrict access to the entire config folder
        icacls $env:windir\system32\config /remove:g Everyone
        icacls $env:windir\system32\config /remove:g "BUILTIN\Users"

        # Restore correct inheritance for SAM and config folder
        icacls $env:windir\system32\config\sam /inheritance:e
        icacls $env:windir\system32\config /inheritance:e

        Write-Host "*** Successfully secured the system! No more unauthorized access." -ForegroundColor Green
    }
    catch {
        Write-Host "*** Failed to secure access!!: " -ForegroundColor Red
        Write-Host "    `"$_`" " -ForegroundColor DarkMagenta
    }
}
else {
    Write-Host "System is not vulnerable. Moving on..." -ForegroundColor Green
}

<# 
- Shadow Copy Cleanup -
#>
if ($listEm) {
    Write-Host "`n`n*** Vulnerable shadow found!" -ForegroundColor Yellow
    try {
        Write-Host "*** Deleting Shadow Copies...`n" -ForegroundColor Yellow
        vssadmin delete shadows /for=$env:SystemDrive /Quiet
        sleepy -time 1
        Write-Host "`n`n*** Success! Shadow copies removed.`n" -ForegroundColor Green
    }
    catch {
        Write-Host "Deletion Failed`n" -ForegroundColor Red
    }
}
else {
    Write-Host "No vulnerable shadow copies found. Moving on...`n" -ForegroundColor Green
}