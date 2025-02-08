# Notes on NOCorp's project: HIVENightmare and PrintNIghtMare. 

+ [ ] A script to Detect if the HiveNightmare problem exists

- [ ] A script to Remediate the HiveNightmare problem and remove existing Shadow Copies

<p>&nbsp;</p>
    
## CVE-2021-34527 - PrintNightmare


### Detection
        
#### Group Policy settings are correct:
- HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsNT\Printers\PointAndPrint
    - ``NoWarningNoElevationOnInstall = 0 (DWORD)`` or not defined (default setting)
    - ``UpdatePromptSettings = 0 (DWORD)`` or not defined (default setting)

#### Also check if registry Key value exists and is configured:

`RestrictDriverInstallationToAdministrators = 0` 


#### Determine if the Print Spooler service is running:

```Get-Service -Name Spooler```

#### CHeck registry:

`Get-ItemProperty HKLM:HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint -Name "RestrictDriverInstallationToAdministrators"`


#### Microsoft Defender Hunting Queries -- adapt to script

Look for the creation of suspicious DLL files spawned in the \spool\ folder along with DLLs that were recently loaded afterwards from \Old. Query:

```
DeviceFileEvents
| where FolderPath contains @"\system32\spool\drivers\x64\3\"
| where FileName endswith ".dll"
| where ActionType in ("FileCreated", "FileRenamed")
| join kind=inner DeviceImageLoadEvents on DeviceId,DeviceName,FileName,InitiatingProcessFileName
| where Timestamp1 >= Timestamp and FolderPath1 contains @"\system32\spool\drivers\x64\3\Old"
```



Creation of suspicious files in the /spools/driver/ folder. This is a broad-based search that will surface any creation or modification of files in the folder targeted by this exploit. False Positives for legitimate driver activity (when that activity should be present) in this folder are possible:

```
DeviceFileEvents
| where FolderPath has @"System32\spool\drivers"
| project DeviceName,Timestamp,ActionType,FolderPath,FileName,SHA1
```
<p>&nbsp;</p>

### Removal and Remediation 

### Modify the default driver installation behavior using a registry key

    Automate the addition of RestrictDriverInstallationToAdministrators registry value

    To automate the addition of the RestrictDriverInstallationToAdministrators registry value, follow these steps:

        Open a Command Prompt window (cmd.exe) with elevated permissions.

        Type the following command and then press Enter:

        reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f

    Set RestrictDriverInstallationToAdministrators using Group Policy

    After installing updates released October 12, 2021 or later, you can also set RestrictDriverInstallationToAdministrators using a Group Policy, using the following instructions:

        Open the group policy editor tool and go to Computer Configuration > Administrative Templates > Printers. 

        Set the Limits print driver installation to Administrators setting to "Enabled". This will set the registry value of RestrictDriverInstallationToAdministrators to 1.
    
 >*Source: https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872*

<p>&nbsp;</p>
<p>&nbsp;</p>

## CVE-2021-36934 - HiveNightmare

### Detection

#### - Verify Shadow Copy/Removal:
`vssadmin list shadows`

#### - From non-privshell, check if a system is vulnerable:
A vulnerable system will report `BUILTIN\Users:(I)(RX)` in the output

`icacls $env:windir\system32\config\sam`

<p>&nbsp;</p>

### Removal and Remediation

#### - Remove Shadow Copies:
`vssadmin delete shadows /for=%systemdrive% /Quiet`


#### - Restrict access to the contents of %windir%\system32\config
*This could be a way to verify the return for compliance check*

`icacls $env:windir\system32\config\*.* /inheritance:e`  
  
>*Source: https://www.kb.cert.org/vuls/id/506989*



