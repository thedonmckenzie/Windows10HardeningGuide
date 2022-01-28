# Windows 10 Hardening Guide - Setting Applicable Registry Keys via PowerShell based on https://www.cyber.gov.au/acsc/view-all-content/publications/hardening-microsoft-windows-10-version-21h1-workstations
# This script looks to set as many of of the recommendations as possible, without using Group Policy (to allow for non Windows Pro licenced users).

	# Workstations are often targeted by an adversary using malicious websites, emails or removable media in an attempt to extract sensitive information. Hardening workstations 
	# is an important part of reducing this risk.
	# The ACSC provides recommendations on hardening workstations using Enterprise and Education editions of Microsoft Windows 10 version 21H1. Before implementing 
	# recommendations in this publication, thorough testing should be undertaken to ensure the potential for unintended negative impacts on business processes is reduced as much as possible.
	# While this publication refers to workstations, most recommendations are equally applicable to servers (with the exception of Domain Controllers) using Microsoft Windows 
	# Server version 21H1 or Microsoft Windows Server 2019.
	# Security features discussed in this publication, along with the names and locations of Group Policy settings, are taken from Microsoft Windows 10 version 21H1 – some 
	# differences will exist for earlier versions of Microsoft Windows 10.
	# For cloud-based device managers, such as Microsoft Endpoint Manager, equivalents can be found for many of the Group Policy settings. Alternatively, there is often a 
	# function to import Group Policy settings into cloud-based device managers.

# Application Hardening
        Write-Host "`n"
        Write-Host "Application Hardening" -ForegroundColor Yellow
		Write-Host "Please review comments of this script for more information" -ForegroundColor Green
	# When applications are installed they are often not pre-configured in a secure state. By default, many applications enable functionality that isn’t required by any users 
	# while in-built security functionality may be disabled or set at a lower security level. For example, Microsoft Office by default allows untrusted macros in Office 
	# documents to automatically execute without user interaction. To reduce this risk, applications should have any in-built security functionality enabled and appropriately 
	# configured along with unrequired functionality disabled. This is especially important for key applications such as office productivity suites (e.g. Microsoft Office), 
	# PDF readers (e.g. Adobe Reader), web browsers (e.g. Microsoft Internet Explorer, Mozilla Firefox or Google Chrome), common web browser plugins (e.g. Adobe Flash), 
	# email clients (Microsoft Outlook) and software platforms (e.g. Oracle Java Platform and Microsoft .NET Framework). In addition, vendors may provide guidance on configuring 
	# their products securely. For example, Microsoft provides security baselines for their products on their Microsoft Security Baseline Blog. In such cases, vendor guidance 
	# should be followed to assist in securely configuring their products.
	# The Australian Cyber Security Centre also provides guidance for hardening Microsoft Office. For more information see the Hardening Microsoft 365, Office 2021, 
	# Office 2019 and Office 2016 publication. https://www.cyber.gov.au/acsc/view-all-content/publications/hardening-microsoft-365-office-2021-office-2019-and-office-2016

# Application versions and patches
        Write-Host "`n"
        Write-Host "Application versions and patches" -ForegroundColor Yellow
		Write-Host "Please review comments of this script for more information" -ForegroundColor Green
	# While some vendors may release new application versions to address security vulnerabilities, others may release patches. If new application versions and patches 
	# for applications are not installed it can allow an adversary to easily compromise workstations. This is especially important for key applications that interact 
	# with content from untrusted sources such as office productivity suites (e.g. Microsoft Office), PDF readers (e.g. Adobe Reader), web browsers (e.g. Microsoft Internet Explorer, 
	# Mozilla Firefox or Google Chrome), common web browser plugins (e.g. Adobe Flash), email clients (Microsoft Outlook) and software platforms (e.g. Oracle Java Platform and 
	# Microsoft .NET Framework). To reduce this risk, new application versions and patches for applications should be applied in an appropriate timeframe as determined by the 
	# severity of security vulnerabilities they address and any mitigating measures already in place. In cases where a previous version of an application continues to receive 
	# support in the form of patches, it still should be upgraded to the latest version to receive the benefit of any new security functionality.
	# https://www.cyber.gov.au/acsc/view-all-content/publications/assessing-security-vulnerabilities-and-applying-patches
	
# Application control
        Write-Host "`n"
        Write-Host "Application control" -ForegroundColor Yellow
		Write-Host "Please review comments of this script for more information" -ForegroundColor Green
	# An adversary can email malicious code, or host malicious code on a compromised website, and use social engineering techniques to convince users into executing it. 
	# Such malicious code often aims to exploit security vulnerabilities in existing applications and does not need to be installed to be successful. Application control 
	# can be an extremely effective mechanism in not only preventing malicious code from executing, but also ensuring only approved applications can be installed.
	# When developing application control rules, starting from scratch is a more secure method than relying on a list of executable content currently residing on a 
	# workstation. Furthermore, it is preferable that organisations define their own application control ruleset rather than relying on rulesets from application control 
	# vendors. This application control ruleset should then be regularly assessed to determine if it remains fit for purpose.
	# For more information on application control and how it can be appropriately implemented see the Implementing Application Control publication.	
	# https://www.cyber.gov.au/acsc/view-all-content/publications/implementing-application-control

# Attack Surface Reduction
        Write-Host "`n"
        Write-Host "Attack Surface Reduction" -ForegroundColor Yellow
	# Attack Surface Reduction (ASR), a security feature of Microsoft Windows 10, forms part of Microsoft Defender Exploit Guard. It is designed to combat the threat 
	# of malware exploiting legitimate functionality in Microsoft Office applications. In order to use ASR, Microsoft Defender Antivirus must be configured as the primary 
	# real-time antivirus scanning engine on workstations.
	# ASR offers a number of attack surface reduction rules, these include:

	# Block executable content from email client and webmail
		Set-MPPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions 1
			Write-Host "Block executable content from email client and webmail" -ForegroundColor Green
	# Block all Office applications from creating child processes
		Set-MPPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions 1
			Write-Host "Block all Office applications from creating child processes" -ForegroundColor Green
	# Block Office applications from creating executable content
		Set-MPPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions 1
			Write-Host "Block Office applications from creating executable content" -ForegroundColor Green
	# Block Office applications from injecting code into other processes
		Set-MPPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions 1
			Write-Host "Block Office applications from injecting code into other processes" -ForegroundColor Green		
	# Block JavaScript or VBScript from launching downloaded executable content
		Set-MPPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions 1
			Write-Host "Block JavaScript or VBScript from launching downloaded executable content" -ForegroundColor Green		
	# Block execution of potentially obfuscated scripts
		Set-MPPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions 1
			Write-Host "Block execution of potentially obfuscated scripts" -ForegroundColor Green		
	# Block Win32 API calls from Office macro
		Set-MPPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions 1
			Write-Host "Block Win32 API calls from Office macro" -ForegroundColor Green		
	# Block executable files from running unless they meet a prevalence, age, or trusted list criterion
		Set-MPPreference -AttackSurfaceReductionRules_Ids 01443614-CD74-433A-B99E-2ECDC07BFC25 -AttackSurfaceReductionRules_Actions 1
			Write-Host "Block executable files from running unless they meet a prevalence, age, or trusted list criterion" -ForegroundColor Green		
	# Use advanced protection against ransomware
		Set-MPPreference -AttackSurfaceReductionRules_Ids C1DB55AB-C21A-4637-BB3F-A12568109D35 -AttackSurfaceReductionRules_Actions 1
			Write-Host "Use advanced protection against ransomware" -ForegroundColor Green		
	# Block credential stealing from the Windows local security authority subsystem (lsass.exe)
		Set-MPPreference -AttackSurfaceReductionRules_Ids 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 -AttackSurfaceReductionRules_Actions 1
			Write-Host "Block credential stealing from the Windows local security authority subsystem (lsass.exe)" -ForegroundColor Green		
	# Block process creations originating from PSExec and WMI commands
		Set-MPPreference -AttackSurfaceReductionRules_Ids D1E49AAC-8F56-4280-B9BA-993A6D77406C -AttackSurfaceReductionRules_Actions 1
			Write-Host "Block process creations originating from PSExec and WMI commands" -ForegroundColor Green		
	# Block untrusted and unsigned processes that run from USB
		Set-MPPreference -AttackSurfaceReductionRules_Ids B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4 -AttackSurfaceReductionRules_Actions 1
			Write-Host "Block untrusted and unsigned processes that run from USB" -ForegroundColor Green		
	# Block Office communication application from creating child processes
		Set-MPPreference -AttackSurfaceReductionRules_Ids 26190899-1602-49E8-8B27-EB1D0A1CE869 -AttackSurfaceReductionRules_Actions 1
			Write-Host "Block Office communication application from creating child processes" -ForegroundColor Green		
	# Block Adobe Reader from creating child processes
		Set-MPPreference -AttackSurfaceReductionRules_Ids 7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C -AttackSurfaceReductionRules_Actions 1
			Write-Host "Block Adobe Reader from creating child processes" -ForegroundColor Green		
	# Block persistence through WMI event subscription
		Set-MPPreference -AttackSurfaceReductionRules_Ids E6DB77E5-3DF2-4CF1-B95A-636979351E5B -AttackSurfaceReductionRules_Actions 1
			Write-Host "Block persistence through WMI event subscription" -ForegroundColor Green

# Credential Caching
        Write-Host "`n"
        Write-Host "Credential caching" -ForegroundColor Yellow

    # Cached credentials are stored in the Security Accounts Manager (SAM) database and can allow a user to log onto a workstation they have 
    # previously logged onto even if the domain is not available. Whilst this functionality may be desirable from an availability of services perspective, 
    # this functionality can be abused by an adversary who can retrieve these cached credentials (potentially Domain Administrator credentials in a worst-case scenario). 
	# To reduce this risk, cached credentials should be limited to only one previous logon.
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
    # Another key security feature of Trusted Boot, supported by Microsoft Windows 10 and motherboards with an Unified Extensible Firmware Interface (UEFI), is Early Launch Antimalware (ELAM). 
	# Used in conjunction with Secure Boot, an ELAM driver can be registered as the first non-Microsoft driver that will be initialised on a workstation as part of the boot process, 
	# thus allowing it to verify all subsequent drivers before they are initialised. The ELAM driver is capable of allowing only known good drivers to initialise; known good and unknown drivers 
	# to initialise; known good, unknown and bad but critical drivers to initialise; or all drivers to initialise. To reduce the risk of malicious drivers, only known good and unknown drivers 
	# should be allowed to be initialised during the boot process.Another key security feature of Trusted Boot supported by Microsoft Windows 10 version 1709 and 
	# motherboards with an Unified Extensible Firmware Interface (UEFI) 
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
			Write-Host "Admin Approval Mode for the Built-in Administrator account has been enabled" -ForegroundColor Green
    # User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableUIADesktopToggle -Value 0  
			Write-Host "Allow UIAccess applications to prompt for elevation without using the secure desktop has been enabled" -ForegroundColor Green
    # User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name ConsentPromptBehaviorAdmin -Value 1 
			Write-Host "Behavior of the elevation prompt for administrators in Admin Approval Mode has been enabled" -ForegroundColor Green
    # User Account Control: Behavior of the elevation prompt for standard users
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name ConsentPromptBehaviorUser -Value 1 
			Write-Host "Behavior of the elevation prompt for standard users has been enabled" -ForegroundColor Green
    # User Account Control: Detect application installations and prompt for elevation
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableInstallerDetection -Value 1 
			Write-Host "Detect application installations and prompt for elevation has been enabled" -ForegroundColor Green
    # User Account Control: Only elevate UIAccess applications that are installed in secure locations
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableSecureUIAPaths -Value 1 
			Write-Host "Only elevate UIAccess applications that are installed in secure locations has been enabled" -ForegroundColor Green
    # User Account Control: Run all administrators in Admin Approval Mode
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -Value 1 
			Write-Host "Run all administrators in Admin Approval Mode has been enabled" -ForegroundColor Green
    # User Account Control: Switch to the secure desktop when prompting for elevation
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name PromptOnSecureDesktop -Value 1 
			Write-Host "Switch to the secure desktop when prompting for elevation has been enabled" -ForegroundColor Green
    # User Account Control: Virtualize file and registry write failures to per-user locations
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableVirtualization -Value 1 
			Write-Host "Virtualize file and registry write failures to per-user locations has been enabled" -ForegroundColor Green
		
# Exploit Protection
        Write-Host "`n"
        Write-Host "Exploit Protection" -ForegroundColor Yellow
    # An adversary that develops exploits for Microsoft Windows or third party applications will have a higher success rate when security measures designed by 
	# Microsoft to help prevent security vulnerabilities from being exploited are not implemented. Microsoft Defender’s exploit protection functionality, a 
	# security feature of Microsoft Windows 10, provides system-wide and application-specific security measures. Exploit protection is designed to replace the 
	# Enhanced Mitigation Experience Toolkit (EMET) that was used on earlier versions of Microsoft Windows 10.
	# System-wide security measures configurable via exploit protection include: Control Flow Guard (CFG), Data Execution Prevention (DEP), mandatory 
	# Address Space Layout Randomization (ASLR), bottom-up ASLR, Structured Exception Handling Overwrite Protection (SEHOP) and heap corruption protection.
	# Many more application-specific security measures are also available, however, they will require testing (either within a test environment or using audit mode) 
	# beforehand to limit the likelihood of any unintended consequences. As such, a staged approach to implementing application-specific security measures is prudent. 
	# In doing so, applications that ingest arbitrary untrusted data from the internet should be prioritised.
	
	# Use a common set of exploit protection settings 
		Set-ItemProperty -Path "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender ExploitGuard\Exploit Protection" -Name ExploitProtectionSettings -Value 1 
		# (These should be set in an XML)
			Write-Host "Use a common set of exploit protection settings " -ForegroundColor Green
		
	# Prevent users from modifying settings
		Set-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection" -Name DisallowExploitProtectionOverride -Value 1 
			Write-Host "Prevent users from modifying settings has been enabled" -ForegroundColor Green
		
	# Turn off Data Execution Prevention for Explorer
		Set-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\Explorer" -Name NoDataExecutionPrevention -Value 0
			Write-Host "Turn off Data Execution Prevention for Explorer has been disabled" -ForegroundColor Green

	# Enabled Structured Exception Handling Overwrite Protection (SEHOP)
		Set-ItemProperty -Path "Registry::HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\" -Name DisableExceptionChainValidation -Value 0
			Write-Host "Enabled Structured Exception Handling Overwrite Protection (SEHOP)" -ForegroundColor Green

# Local Administrator Accounts
        Write-Host "`n"
        Write-Host "Local Administrator Accounts" -ForegroundColor Yellow

	# When built-in administrator accounts are used with common account names and passwords it can allow an adversary that compromises these credentials on 
	# one workstation to easily transfer across the network to other workstations. Even if built-in administrator accounts are uniquely named and have unique 
	# passwords, an adversary can still identify these accounts based on their security identifier (i.e. S-1-5-21-domain-500) and use this information to focus 
	# any attempts to brute force credentials on a workstation if they can get access to the SAM database. To reduce this risk, built-in administrator accounts 
	# should be disabled. Instead, domain accounts with local administrative privileges, but without domain administrative privileges, should be used for workstation management.

	# Accounts: Administrator account status
		Disable-LocalUser -Name “Administrator”
			Write-Host "In Built Administrator Account Disabled" -ForegroundColor Green

	# If a common local administrator account absolutely must be used for workstation management then Microsoft’s Local Administrator Password Solution (LAPS) 
	# needs to be used to ensure unique passphrases are used for each workstation. In addition, User Account Control restrictions should be applied to remote 
	# connections using such accounts. Note, the MS Security Guide Group Policy settings are available as part of the Microsoft Security Compliance Toolkit.

	# Apply UAC restrictions to local accounts on network logons 
		Set-ItemProperty -Path "Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name LocalAccountTokenFilterPolicy -Value 0
			Write-Host "Apply UAC restrictions to local accounts on network logons" -ForegroundColor Green

# Measured Boot
        Write-Host "`n"
        Write-Host "Measured Boot" -ForegroundColor Yellow
		Write-Host "Please review comments of this script for more information" -ForegroundColor Green
		
	# The third key security feature of Trusted Boot, supported by Microsoft Windows 10 and motherboards with both an UEFI and a Trusted Platform Module (TPM), 
	# is Measured Boot. Measured Boot is used to develop a reliable log of components that are initialised before the ELAM driver. This information can then be 
	# scrutinised by antimalware software for signs of tampering of boot components. To reduce the risk that malicious changes to boot components go unnoticed, 
	# Measured Boot should be used on workstations that support it.

# Microsoft Edge
        Write-Host "`n"
        Write-Host "Microsoft Edge" -ForegroundColor Yellow
		
	# Microsoft Edge is a web browser that was first introduced in Microsoft Windows 10 to replace Internet Explorer 11. Microsoft Edge contains significant 
	# security enhancements (the most recent version being based on the Chromium project) over Internet Explorer 11 and should be used wherever possible. 
	# Furthermore, as Microsoft Edge contains an ‘IE mode’, Internet Explorer 11 should be disabled or removed from Microsoft Windows 10 to reduce the operating 
	# system’s attack surface.

	# Allow Adobe Flash 
		Set-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\MicrosoftEdge\Addons\" -Name FlashPlayerEnabled -Value 0
			Write-Host "Adobe Flash is disabled in Local Machine GP" -ForegroundColor Green		
		Set-ItemProperty -Path "Registry::HKCU\Software\Policies\Microsoft\MicrosoftEdge\Addons\" -Name FlashPlayerEnabled -Value 0
			Write-Host "Adobe Flash is disabled in User GP" -ForegroundColor Green

	# Allow Developer Tools
		Set-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\MicrosoftEdge\F12\" -Name AllowDeveloperTools -Value 0
			Write-Host "Edge Developer Tools are disabled in Local Machine GP" -ForegroundColor Green
		Set-ItemProperty -Path "Registry::HKCU\Software\Policies\Microsoft\MicrosoftEdge\F12\" -Name AllowDeveloperTools -Value 0 
			Write-Host "Edge Developer Tools are disabled in User GP" -ForegroundColor Green

	# Configure Do Not Track
		Set-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\MicrosoftEdge\Main\" -Name DoNotTrack -Value 1 
			Write-Host "Edge Do Not Track is enabled in Local Machine GP" -ForegroundColor Green
		Set-ItemProperty -Path "Registry::HKCU\Software\Policies\Microsoft\MicrosoftEdge\Main\" -Name DoNotTrack -Value 1
			Write-Host "Edge Do Not Track is enabled in User GP" -ForegroundColor Green

	# Configure Password Manager
		Set-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\MicrosoftEdge\Main\" -Name 'FormSuggest Passwords' -Value yes
			Write-Host "Edge Password Manager is enabled in Local Machine GP" -ForegroundColor Green
		Set-ItemProperty -Path "Registry::HKCU\Software\Policies\Microsoft\MicrosoftEdge\Main\" -Name 'FormSuggest Passwords' -Value yes
			Write-Host "Edge Password Manager is enabled in User GP" -ForegroundColor Green

	# Configure Pop-up Blocker
		Set-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\MicrosoftEdge\Main\" -Name AllowPopups -Value yes
			Write-Host "Edge Pop-up Blocker is enabled in Local Machine GP" -ForegroundColor Green
		Set-ItemProperty -Path "Registry::HKCU\Software\Policies\Microsoft\MicrosoftEdge\Main\" -Name AllowPopups -Value yes
			Write-Host "Edge Pop-up Blocker is enabled in User GP" -ForegroundColor Green

	# Configure Windows Defender SmartScreen
		Set-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System\ -Name EnableSmartScreen -Value 1
			Write-Host "Configure Windows Defender SmartScreen is enabled" -ForegroundColor Green

	# Prevent access to the about:flags page in Microsoft Edge is disabled in User GP
		Set-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\MicrosoftEdge\Main\" -Name PreventAccessToAboutFlagsInMicrosoftEdge -Value 1
			Write-Host "Prevent access to the about:flags page in Microsoft Edge is enabled in Local Machine GP" -ForegroundColor Green
		Set-ItemProperty -Path "Registry::HKCU\Software\Policies\Microsoft\MicrosoftEdge\Main\" -Name PreventAccessToAboutFlagsInMicrosoftEdge -Value 1
			Write-Host "Prevent access to the about:flags page in Microsoft Edge is enabled in User GP" -ForegroundColor Green

	# Prevent bypassing Windows Defender SmartScreen prompts for sites is not configured
		Set-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter\" -Name PreventOverride -Value 1
			Write-Host "Prevent bypassing Windows Defender SmartScreen prompts for sites is enabled in Local Machine GP" -ForegroundColor Green
		Set-ItemProperty -Path "Registry::HKCU\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter\" -Name PreventOverride -Value 1
			Write-Host "Prevent bypassing Windows Defender SmartScreen prompts for sites is enabled in User GP" -ForegroundColor Green

	# Prevent users and apps from accessing dangerous websites
		Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection\' -Name EnableNetworkProtection -Value 1
			Write-Host "Prevent users and apps from accessing dangerous websites is enabled" -ForegroundColor Green

	# Check Turn on Windows Defender Application Guard in Enterprise Mode
		Set-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\AppHVSI\ -Name AllowAppHVSI_ProviderSet -Value 1
			Write-Host "Turn on Windows Defender Application Guard in Enterprise Mode is enabled" -ForegroundColor Green

	# Configure Windows Defender SmartScreen 
		Set-ItemProperty -Path Registry::HKLM\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter\ -Name EnabledV9 -Value 1
			Write-Host "Configure Windows Defender SmartScreen is enabled in Local Machine GP" -ForegroundColor Green
		Set-ItemProperty -Path Registry::HKCU\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter\ -Name EnabledV9 -Value 1
			Write-Host "Configure Windows Defender SmartScreen is enabled in User GP" -ForegroundColor Green

	# Prevent bypassing Windows Defender SmartScreen prompts for sites
		Set-ItemProperty -Path Registry::HKLM\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter\ -Name PreventOverride -Value 1
			Write-Host "Prevent bypassing Windows Defender SmartScreen prompts for sites is enabled in Local Machine GP" -ForegroundColor Green
		Set-ItemProperty -Path Registry::HKCU\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter\ -Name PreventOverride -Value 1
			Write-Host "Prevent bypassing Windows Defender SmartScreen prompts for sites is enabled in User GP" -ForegroundColor Green
			
# Multi-factor authentication
        Write-Host "`n"
        Write-Host "Multi-factor authentication" -ForegroundColor Yellow
		Write-Host "Please review comments of this script for more information" -ForegroundColor Green

	# As privileged credentials often allow users to bypass security functionality put in place to protect workstations, and are susceptible 
	# to key logging applications, it is important that they are appropriately protected against compromise. In addition, an adversary that 
	# brute forces captured password hashes can gain access to workstations if multi-factor authentication hasn’t been implemented. To reduce 
	# this risk, hardware-based multi-factor authentication should be used for privileged users, remote access and any access to important 
	# or sensitive data repositories.
	# Organisations may consider whether Windows Hello for Business (WHfB) is suitable for their environment. Notably, WHfB can be configured 
	# with a personal identification number (PIN) or face/fingerprint recognition to unlock the use of asymmetric cryptography stored in a 
	# TPM in order to authenticate users. Note, the use of TPMs places additional importance on patching TPMs for security vulnerabilities 
	# and decommissioning those devices that are not able to be patched. Organisations may also choose to enforce the use of the latest 
	# versions of TPMs when using WHfB. Finally, Microsoft has issued guidance on the use of FIDO2 security tokens as part of multi-factor 
	# authentication for Microsoft Windows logons.
	# For more information on how to effectively implement multi-factor authentication see the Implementing Multi-Factor Authentication publication.
	# https://www.cyber.gov.au/acsc/view-all-content/publications/implementing-multi-factor-authentication

# Operating system architecture
        Write-Host "`n"
        Write-Host "Operating system architecture" -ForegroundColor Yellow

	# The x64 (64-bit) versions of Microsoft Windows include additional security functionality that the x86 (32-bit) versions lack. 
	# This includes native hardware-based Data Execution Prevention (DEP) kernel support, Kernel Patch Protection (PatchGuard), mandatory device 
	# driver signing and lack of support for malicious 32-bit drivers. Using x86 (32-bit) versions of Microsoft Windows exposes organisations 
	# to exploit techniques mitigated by x64 (64-bit) versions of Microsoft Windows. To reduce this risk, workstations should use 
	# the x64 (64-bit) versions of Microsoft Windows.

	# Operating System Architecture
		Write-Host "The Operating System Architecture is" -ForegroundColor Green $ENV:PROCESSOR_ARCHITECTURE

# Operating system patching
        Write-Host "`n"
        Write-Host "Operating system patching" -ForegroundColor Yellow

	# Patches are released either in response to previously disclosed security vulnerabilities or to proactively address security vulnerabilities 
	# that have not yet been publicly disclosed. In the case of disclosed security vulnerabilities, it is possible that exploits have already been 
	# developed and are freely available in common hacking tools. In the case of patches for security vulnerabilities that have not yet been 
	# publically disclosed, it is relatively easy for an adversary to use freely available tools to identify the security vulnerability being 
	# patched and develop an associated exploit. This activity can be undertaken in less than one day and has led to an increase in 1-day attacks. 
	# To reduce this risk, operating system patches and driver updates should be centrally managed, deployed and applied in an appropriate timeframe 
	# as determined by the severity of the security vulnerability and any mitigating measures already in place.
	# Previously, operating system patching was typically achieved by using Microsoft Endpoint Configuration Manager, or Microsoft Windows Server 
	# Update Services (WSUS), along with Wake-on-LAN functionality to facilitate patching outside of core business hours. However, Windows Update 
	# for Business may replace or supplement many WSUS functions. Configuration of Windows Update for Business can be applied through Group Policy 
	# settings or the equivalent settings in Microsoft Endpoint Manager. Microsoft has also issued guidance on common misconfigurations relating 
	# to Windows updates.
	# For more information on determining the severity of security vulnerabilities and timeframes for applying patches see the Assessing Security 
	# Vulnerabilities and Applying Patches publication. https://www.cyber.gov.au/acsc/view-all-content/publications/assessing-security-vulnerabilities-and-applying-patches

	# Automatic Updates immediate installation
		Set-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\ -Name AutoInstallMinorUpdates -Value 1
			Write-Host "Allow Automatic Updates immediate installation is enabled" -ForegroundColor Green

	# Configure Automatic Updates
		Set-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\ -Name NoAutoUpdate -Value 0
			Write-Host "Configure Automatic Updates is enabled" -ForegroundColor Green

	# Do not include drivers with Windows Updates
		Set-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\ -Name ExcludeWUDriversInQualityUpdate -Value 0
			Write-Host "Do not include drivers with Windows Updates is enabled" -ForegroundColor Green

	# No auto-restart with logged on users for scheduled automatic updates installations
		Set-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\ -Name NoAutoRebootWithLoggedOnUsers -Value 1
			Write-Host "No auto-restart with logged on users for scheduled automatic updates installations is enabled" -ForegroundColor Green

	# Remove access to use all Windows Update features
		Set-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\ -Name SetDisableUXWUAccess -Value 0
			Write-Host "Remove access to use all Windows Update features is enabled" -ForegroundColor Green
			
	# Turn on recommended updates via Automatic Updates
		Set-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\ -Name IncludeRecommendedUpdates -Value 1
			Write-Host "Turn on recommended updates via Automatic Updates is enabled" -ForegroundColor Green
			
	# Specify intranet Microsoft update service location (If intranet WSUS is used)
	# 	Set-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\ -Name UseWUServer -Value 1
	#		Write-Host "Do not include drivers with Windows Updates is enabled" -ForegroundColor Green

# Operating system version
        Write-Host "`n"
        Write-Host "Operating system version" -ForegroundColor Yellow
		
	# Microsoft Windows 10 has introduced improvements in security functionality over previous versions of Microsoft Windows. This has made it more 
	# difficult for an adversary to craft reliable exploits for security vulnerabilities they discovered. Using older versions of Microsoft Windows, 
	# including previous versions of Microsoft Windows 10, exposes organisations to exploit techniques that have since been mitigated in newer versions 
	# of Microsoft Windows. To reduce this risk, workstations should use the latest version of Microsoft Windows 10.		
		Write-Host "Current Windows Version:" -ForegroundColor White
		[environment]::OSVersion.Version
	
# Restricting privileged accounts
        Write-Host "`n"
        Write-Host "Restricting privileged accounts" -ForegroundColor Yellow
		Write-Host "Please review comments of this script for more information" -ForegroundColor Green
		
	# Providing users with a privileged account for day to day usage poses a risk that they will use this account for external web and email access. 
	# This is of particular concern as privileged users have the ability to execute malicious code with privileged access rather than standard access. 
	# To reduce this risk, users that don’t require privileged access should not be granted privileged accounts while users that require privileged access 
	# should have separate standard and privileged accounts with different credentials. In addition, any privileged accounts used should have 
	# external web and email access blocked.
	# For more information on the use of privileged accounts and minimising their usage see the Restricting Administrative Privileges publication.
	# https://www.cyber.gov.au/acsc/view-all-content/publications/restricting-administrative-privileges
		
# Secure Boot
        Write-Host "`n"
        Write-Host "Secure Boot" -ForegroundColor Yellow

	# Another method for malicious code to maintain persistence and prevent detection is to replace the default boot loader for Microsoft 
	# Windows with a malicious version. In such cases the malicious boot loader executes at boot time and loads Microsoft Windows without any 
	# indication that it is present. Such malicious boot loaders are extremely difficult to detect and can be used to conceal malicious code on workstations. 
	# To reduce this risk, motherboards with Secure Boot functionality should be used. Secure Boot, a component of Trusted Boot, is a security feature 
	# of Microsoft Windows 10 and motherboards with an UEFI. Secure Boot works by checking at boot time that the boot loader is signed and matches a 
	# Microsoft signed certificate stored in the UEFI. If the certificate signatures match the boot loader is allowed to run, otherwise it is 
	# prevented from running and the workstation will not boot.

		Write-Host "Is SecureBoot Enabled" -ForegroundColor White
		Confirm-SecureBootUEFI
	
