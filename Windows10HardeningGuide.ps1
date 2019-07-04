# Windows 10 Hardening Guide - Setting Applicable Registry Keys via PowerShell based on https://www.cyber.gov.au/publications/hardening-microsoft-windows-10-build-1709
# Application whitelisting and Attack Surface Reduction are recommended, although not set by this script. See https://www.cyber.gov.au/publications/implementing-application-whitelisting

# Credential Caching
        Write-Host "`n"
        Write-Host "Credential caching" -ForegroundColor Yellow

    # Cached credentials are stored in the Security Accounts Manager (SAM) database and can allow a user to log onto a workstation they have 
    # previously logged onto even if the domain is not available. Whilst this functionality may be desirable from an availability of services perspective, 
    # this functionality can be abused by an adversary who can retrieve these cached credentials (potentially Domain Administrator credentials in a worst-case scenario). To reduce this risk, cached credentials should be limited to only one previous logon.
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\winlogon" -Name CachedLogonsCount -Value 1 -ErrorAction SilentlyContinue
        Write-Host "Number of previous logons to cache (in case domain controller is not available) has been set to '1'" -ForegroundColor Green

    # Do not allow storage of passwords and credentials for network authentication
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\" -Name disabledomaincreds -Value 1 -ErrorAction SilentlyContinue
        Write-Host "Allow storage of passwords and credentials for network authentication has been disabled" -ForegroundColor Green

    # Within an active user session, credentials are cached within the Local Security Authority Subsystem Service (LSASS) process 
    # (including the user’s passphrase in plaintext if WDigest authentication is enabled) to allow for access to network resources 
    # without users having to continually enter their credentials. Unfortunately, these credentials are at risk of theft by an adversary. 
    # To reduce this risk, WDigest authentication should be disabled.
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\" -Name uselogoncredential -Value 0 -ErrorAction SilentlyContinue
        Write-Host "WDigest authentication has been disabled" -ForegroundColor Green

    # Credential Guard, a security feature of Microsoft Windows 10, is also designed to assist in protecting the LSASS process.
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\" -Name EnableVirtualizationBasedSecurity -Value 1 -ErrorAction SilentlyContinue

# Controlled Folder Access
        Write-Host "`n"
        Write-Host "Controlled Folder Access" -ForegroundColor Yellow
    # Controlled Folder Access is a security feature in Microsoft Windows 10 version 1709 that forms part of Windows Defender Exploit Guard. 
    # It is designed to combat the threat of ransomware. In order to use Controlled Folder Access, Windows Defender Antivirus must be configured 
    # as the primary real-time antivirus scanning engine on workstations. Other third party antivirus solutions may offer similar functionality as 
    # part of their offerings. https://docs.microsoft.com/en-au/windows/security/threat-protection/windows-defender-exploit-guard/controlled-folders-exploit-guard
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exploit Guard\Controlled Folder Access" -Name EnableControlledFolderAccess -Value 1 -ErrorAction SilentlyContinue
        Write-Host "Controlled Folder Access for Exploit Guard has been enabled" -ForegroundColor Green

# Credential Entry
        Write-Host "`n"
        Write-Host "Credential Entry" -ForegroundColor Yellow
    # When users enter their credentials on a workstation it provides an opportunity for malicious code, such as a key logging application, 
    # to capture the credentials. To reduce this risk, users should be authenticated by using a trusted path to enter their credentials on the Secure Desktop.        
    # Dont display network selection UI  
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System" -Name DontDisplayNetworkSelectionUI -Value 1 -ErrorAction SilentlyContinue
        Write-Host "Do not display network selection UI has been enabled" -ForegroundColor Green
    # Enumerate local users on domain joined computers
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System" -Name EnumerateLocalUsers -Value 1 -ErrorAction SilentlyContinue
        Write-Host "Enumerate local users on domain joined computers has been disabled" -ForegroundColor Green
    # Do not display the password reveal button
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CredUI" -Name DisablePasswordReveal -Value 1 -ErrorAction SilentlyContinue
        Write-Host "Do not display the password reveal button has been enabled" -ForegroundColor Green
    # Enumerate administrator accounts on elevation
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI" -Name EnumerateAdministrators -Value 0 -ErrorAction SilentlyContinue
        Write-Host "Enumerate administrator accounts on elevation has been disabled" -ForegroundColor Green
    # Require trusted path for credential entry 
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CredUI" -Name EnableSecureCredentialPrompting -Value 1 -ErrorAction SilentlyContinue
        Write-Host "Require trusted path for credential entry has been enabled" -ForegroundColor Green
