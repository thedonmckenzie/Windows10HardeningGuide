# Windows 10 Hardening Guide - Setting Applicable Registry Keys via PowerShell based on https://www.cyber.gov.au/publications/hardening-microsoft-windows-10-build-1709
# Application whitelisting and Attack Surface Reduction are recommended, although not set by this script. See https://www.cyber.gov.au/publications/implementing-application-whitelisting



# Credential Caching
        Write-Host "`n"
        Write-Host "Credential caching" -ForegroundColor Yellow

    # Cached credentials are stored in the Security Accounts Manager (SAM) database and can allow a user to log onto a workstation they have 
    # previously logged onto even if the domain is not available. Whilst this functionality may be desirable from an availability of services perspective, 
    # this functionality can be abused by an adversary who can retrieve these cached credentials (potentially Domain Administrator credentials in a worst-case scenario). To reduce this risk, cached credentials should be limited to only one previous logon.
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\winlogon" -Name CachedLogonsCount -Value 1 
        Write-Host "Number of previous logons to cache (in case domain controller is not available) has been set to '1'" -ForegroundColor Green

    # Do not allow storage of passwords and credentials for network authentication
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\" -Name disabledomaincreds -Value 1 
        Write-Host "Allow storage of passwords and credentials for network authentication has been disabled" -ForegroundColor Green

    # Within an active user session, credentials are cached within the Local Security Authority Subsystem Service (LSASS) process 
    # (including the user’s passphrase in plaintext if WDigest authentication is enabled) to allow for access to network resources 
    # without users having to continually enter their credentials. Unfortunately, these credentials are at risk of theft by an adversary. 
    # To reduce this risk, WDigest authentication should be disabled.
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\" -Name uselogoncredential -Value 0 
        Write-Host "WDigest authentication has been disabled" -ForegroundColor Green

    # Credential Guard, a security feature of Microsoft Windows 10, is also designed to assist in protecting the LSASS process.
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\" -Name EnableVirtualizationBasedSecurity -Value 1 
        Write-Host "Virtualisation Based Security has been enabled" -ForegroundColor Green

    #Secure Boot and DMA Protection
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name RequirePlatformSecurityFeatures -Value 3 
        Write-Host "Secure Boot and DMA Protection has been enabled" -ForegroundColor Green

    #UEFI Lock is enabled for device guard
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name LsaCfgFlags -Value 1 
        Write-Host "UEFI Lock for device guard has been enabled" -ForegroundColor Green

# Controlled Folder Access
        Write-Host "`n"
        Write-Host "Controlled Folder Access" -ForegroundColor Yellow
    # Controlled Folder Access is a security feature of Microsoft Windows 10, forms part of Microsoft Defender Exploit Guard. 
    # It is designed to combat the threat of ransomware. In order to use Controlled Folder Access, Windows Defender Antivirus must be configured 
    # as the primary real-time antivirus scanning engine on workstations. Other third party antivirus solutions may offer similar functionality as 
    # part of their offerings. https://docs.microsoft.com/en-au/windows/security/threat-protection/windows-defender-exploit-guard/controlled-folders-exploit-guard
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exploit Guard\Controlled Folder Access" -Name EnableControlledFolderAccess -Value 1 
        Write-Host "Controlled Folder Access for Exploit Guard has been enabled" -ForegroundColor Green

# Credential Entry
        Write-Host "`n"
        Write-Host "Credential Entry" -ForegroundColor Yellow
    # When users enter their credentials on a workstation it provides an opportunity for malicious code, such as a key logging application, 
    # to capture the credentials. To reduce this risk, users should be authenticated by using a trusted path to enter their credentials on the Secure Desktop.        
    # Dont display network selection UI  
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System" -Name DontDisplayNetworkSelectionUI -Value 1 
        Write-Host "Do not display network selection UI has been enabled" -ForegroundColor Green
    # Enumerate local users on domain joined computers
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System" -Name EnumerateLocalUsers -Value 1 
        Write-Host "Enumerate local users on domain joined computers has been disabled" -ForegroundColor Green
    # Do not display the password reveal button
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CredUI" -Name DisablePasswordReveal -Value 1 
        Write-Host "Do not display the password reveal button has been enabled" -ForegroundColor Green
    # Enumerate administrator accounts on elevation
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI" -Name EnumerateAdministrators -Value 0 
        Write-Host "Enumerate administrator accounts on elevation has been disabled" -ForegroundColor Green
    # Require trusted path for credential entry 
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CredUI" -Name EnableSecureCredentialPrompting -Value 1 
        Write-Host "Require trusted path for credential entry has been enabled" -ForegroundColor Green
    # Disable or enable software Secure Attention Sequence  
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name SoftwareSASGeneration -Value 0 
        Write-Host "Software Secure Attention Sequence has been disabled" -ForegroundColor Green
    # Sign-in last interactive user automatically after a system-initiated restart 
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name DisableAutomaticRestartSignOn -Value 1 
        Write-Host "Sign-in last interactive user automatically after a system-initiated restart has been disabled" -ForegroundColor Green
    # Do not require CTRL+ALT+DEL 
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name DisableCAD -Value 0 
        Write-Host "Do not require CTRL+ALT+DEL has been disabled" -ForegroundColor Green
    # Don't display username at sign-in 
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name DontDisplayLastUserName -Value 1 
        Write-Host "Don't display username at sign-in has been enabled" -ForegroundColor Green

#Early Launch Antimalware
        Write-Host "`n"
        Write-Host "Early Launch Antimalware (ELAM)" -ForegroundColor Yellow
    # Another key security feature of Trusted Boot supported by Microsoft Windows 10 version 1709 and motherboards with an Unified Extensible Firmware Interface (UEFI) 
    # is Early Launch Antimalware (ELAM). Used in conjunction with Secure Boot, an ELAM driver can be registered as the first non-Microsoft driver that will be initialised 
    # on a workstation as part of the boot process, thus allowing it to verify all subsequent drivers before they are initialised. The ELAM driver is capable of allowing 
    # only known good drivers to initialise; known good and unknown drivers to initialise; known good,
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Policies\EarlyLaunch" -Name DriverLoadPolicy -Value 2 

# Elevating Privleges
        Write-Host "`n"
        Write-Host "Elevating Privleges" -ForegroundColor Yellow
    # Microsoft Windows provides the ability to require confirmation from users, via the User Access Control (UAC) functionality, before any sensitive actions are performed. 
    # The default settings allow privileged users to perform sensitive actions without first providing credentials and while standard users must provide privileged credentials 
    # they are not required to do so via a trusted path on the Secure Desktop. This provides an opportunity for an adversary that gains access to an open session of a 
    # privileged user to perform sensitive actions at will or for malicious code to capture any credentials entered via a standard user when attempting to elevate their 
    # privileges. To reduce this risk, UAC functionality should be implemented to ensure all sensitive actions are authorised by providing credentials on the Secure Desktop.

    # User Account Control: Admin Approval Mode for the Built-in Administrator account
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name FilterAdministratorToken -Value 1 

    # User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableUIADesktopToggle -Value 0  

    # User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name ConsentPromptBehaviorAdmin -Value 1 

    # User Account Control: Behavior of the elevation prompt for standard users
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name ConsentPromptBehaviorUser -Value 1 

    # User Account Control: Detect application installations and prompt for elevation
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableInstallerDetection -Value 1 

    # User Account Control: Only elevate UIAccess applications that are installed in secure locations
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableSecureUIAPaths -Value 1 

    # User Account Control: Run all administrators in Admin Approval Mode
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -Value 1 

    # User Account Control: Switch to the secure desktop when prompting for elevation
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name PromptOnSecureDesktop -Value 1 

    # User Account Control: Virtualize file and registry write failures to per-user locations
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableVirtualization -Value 1 

# Exploit Protection
        Write-Host "`n"
        Write-Host "Exploit Protection" -ForegroundColor Yellow
    # An adversary that develops exploits for Microsoft Windows or third party applications will have a higher success rate when security measures designed 
    # by Microsoft to help prevent security vulnerabilities from being exploited are not implemented. Windows Defender Exploit Guard’s Exploit Protection functionality 
    # was introduced in Microsoft Windows 10 version 1709 to provide system-wide and application-specific security measures. Exploit Protection is designed to replace the 
    # Enhanced Mitigation Experience Toolkit (EMET) that was used on earlier versions of Microsoft Windows 10.
    # System-wide security measures configurable via Exploit Protection include: Control Flow Guard (CFG), Data Execution Prevention (DEP), mandatory Address Space Layout 
    # Randomization (ASLR), bottom-up ASLR, Structured Exception Handling Overwrite Protection (SEHOP) and heap corruption protection. Many more application-specific security 
    # measures are also available.
