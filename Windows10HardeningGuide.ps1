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

#------------------------------------------------------------#
# Application Hardening
#------------------------------------------------------------#
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

#------------------------------------------------------------#
# Application versions and patches
#------------------------------------------------------------#
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

#------------------------------------------------------------#	
# Application control
#------------------------------------------------------------#
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

#------------------------------------------------------------#
# Attack Surface Reduction
#------------------------------------------------------------#
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

#------------------------------------------------------------#
# Credential Caching
#------------------------------------------------------------#
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

    # Secure Boot and DMA Protection
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name RequirePlatformSecurityFeatures -Value 3 
			Write-Host "Secure Boot and DMA Protection has been enabled" -ForegroundColor Green

    # UEFI Lock is enabled for device guard
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name LsaCfgFlags -Value 1 
			Write-Host "UEFI Lock for device guard has been enabled" -ForegroundColor Green

#------------------------------------------------------------#
# Controlled Folder Access
#------------------------------------------------------------#
        Write-Host "`n"
			Write-Host "Controlled Folder Access" -ForegroundColor Yellow
    # Controlled Folder Access is a security feature of Microsoft Windows 10, forms part of Microsoft Defender Exploit Guard. 
    # It is designed to combat the threat of ransomware. In order to use Controlled Folder Access, Windows Defender Antivirus must be configured 
    # as the primary real-time antivirus scanning engine on workstations. Other third party antivirus solutions may offer similar functionality as 
    # part of their offerings. https://docs.microsoft.com/en-au/windows/security/threat-protection/windows-defender-exploit-guard/controlled-folders-exploit-guard
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exploit Guard\Controlled Folder Access" -Name EnableControlledFolderAccess -Value 1 
			Write-Host "Controlled Folder Access for Exploit Guard has been enabled" -ForegroundColor Green

#------------------------------------------------------------#
# Credential Entry
#------------------------------------------------------------#
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

#------------------------------------------------------------#
#Early Launch Antimalware
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "Early Launch Antimalware (ELAM)" -ForegroundColor Yellow
    # Another key security feature of Trusted Boot, supported by Microsoft Windows 10 and motherboards with an Unified Extensible Firmware Interface (UEFI), is Early Launch Antimalware (ELAM). 
	# Used in conjunction with Secure Boot, an ELAM driver can be registered as the first non-Microsoft driver that will be initialised on a workstation as part of the boot process, 
	# thus allowing it to verify all subsequent drivers before they are initialised. The ELAM driver is capable of allowing only known good drivers to initialise; known good and unknown drivers 
	# to initialise; known good, unknown and bad but critical drivers to initialise; or all drivers to initialise. To reduce the risk of malicious drivers, only known good and unknown drivers 
	# should be allowed to be initialised during the boot process.Another key security feature of Trusted Boot supported by Microsoft Windows 10 version 1709 and 
	# motherboards with an Unified Extensible Firmware Interface (UEFI) 
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Policies\EarlyLaunch" -Name DriverLoadPolicy -Value 2 

#------------------------------------------------------------#
# Elevating Privleges
#------------------------------------------------------------#
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

#------------------------------------------------------------#		
# Exploit Protection
#------------------------------------------------------------#
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

#------------------------------------------------------------#
# Local Administrator Accounts
#------------------------------------------------------------#
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

#------------------------------------------------------------#
# Measured Boot
#------------------------------------------------------------#
		Write-Host "`n"
        Write-Host "Measured Boot" -ForegroundColor Yellow
		Write-Host "Please review comments of this script for more information" -ForegroundColor Green
		
	# The third key security feature of Trusted Boot, supported by Microsoft Windows 10 and motherboards with both an UEFI and a Trusted Platform Module (TPM), 
	# is Measured Boot. Measured Boot is used to develop a reliable log of components that are initialised before the ELAM driver. This information can then be 
	# scrutinised by antimalware software for signs of tampering of boot components. To reduce the risk that malicious changes to boot components go unnoticed, 
	# Measured Boot should be used on workstations that support it.

#------------------------------------------------------------#
# Microsoft Edge
#------------------------------------------------------------#
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

#------------------------------------------------------------#			
# Multi-factor authentication
#------------------------------------------------------------#
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

#------------------------------------------------------------#
# Operating system architecture
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "Operating system architecture" -ForegroundColor Yellow

	# The x64 (64-bit) versions of Microsoft Windows include additional security functionality that the x86 (32-bit) versions lack. 
	# This includes native hardware-based Data Execution Prevention (DEP) kernel support, Kernel Patch Protection (PatchGuard), mandatory device 
	# driver signing and lack of support for malicious 32-bit drivers. Using x86 (32-bit) versions of Microsoft Windows exposes organisations 
	# to exploit techniques mitigated by x64 (64-bit) versions of Microsoft Windows. To reduce this risk, workstations should use 
	# the x64 (64-bit) versions of Microsoft Windows.

	# Operating System Architecture
		Write-Host "The Operating System Architecture is" -ForegroundColor Green $ENV:PROCESSOR_ARCHITECTURE
		
#------------------------------------------------------------#
# Operating system patching
#------------------------------------------------------------#
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
	
#------------------------------------------------------------#
# Operating system version
#------------------------------------------------------------#
		Write-Host "`n"
        Write-Host "Operating system version" -ForegroundColor Yellow
		
	# Microsoft Windows 10 has introduced improvements in security functionality over previous versions of Microsoft Windows. This has made it more 
	# difficult for an adversary to craft reliable exploits for security vulnerabilities they discovered. Using older versions of Microsoft Windows, 
	# including previous versions of Microsoft Windows 10, exposes organisations to exploit techniques that have since been mitigated in newer versions 
	# of Microsoft Windows. To reduce this risk, workstations should use the latest version of Microsoft Windows 10.		
		Write-Host "Current Windows Version:" -ForegroundColor White
		[environment]::OSVersion.Version
		
#------------------------------------------------------------#	
# Restricting privileged accounts
#------------------------------------------------------------#
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

#------------------------------------------------------------#		
# Secure Boot
        Write-Host "`n"
        Write-Host "Secure Boot" -ForegroundColor Yellow
#------------------------------------------------------------#

	# Another method for malicious code to maintain persistence and prevent detection is to replace the default boot loader for Microsoft 
	# Windows with a malicious version. In such cases the malicious boot loader executes at boot time and loads Microsoft Windows without any 
	# indication that it is present. Such malicious boot loaders are extremely difficult to detect and can be used to conceal malicious code on workstations. 
	# To reduce this risk, motherboards with Secure Boot functionality should be used. Secure Boot, a component of Trusted Boot, is a security feature 
	# of Microsoft Windows 10 and motherboards with an UEFI. Secure Boot works by checking at boot time that the boot loader is signed and matches a 
	# Microsoft signed certificate stored in the UEFI. If the certificate signatures match the boot loader is allowed to run, otherwise it is 
	# prevented from running and the workstation will not boot.

		Write-Host "Is SecureBoot Enabled" -ForegroundColor White
		Confirm-SecureBootUEFI
		
#------------------------------------------------------------#	
# Account lockout policy
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "Account lockout policy" -ForegroundColor Yellow	
	
	# Allowing unlimited attempts to access workstations will fail to prevent an adversary’s attempts to brute force authentication measures. 
	# To reduce this risk, accounts should be locked out after a defined number of invalid authentication attempts. The threshold for locking out 
	# accounts does not need to be overly restrictive in order to be effective. For example, a threshold of 5 incorrect attempts, with a reset 
	# period of 15 minutes for the lockout counter, will prevent any brute force attempt while being unlikely to lock out a legitimate user who 
	# accidently enters their password incorrectly a few times.	
	
	# Reset Account Lockout Counter
		net accounts /lockoutwindow:15
	# Account Lockout Duration
		net accounts /lockoutduration:15
			Write-Host "Account Lockout is set to 15 minutes" -ForegroundColor Green			
	# Account Lockout Threshold
		net accounts /lockoutthreshold:5
			Write-Host "Account will be locked out after 5 incorrect attempts" -ForegroundColor Green	
			
#------------------------------------------------------------#
# Anonymous connections
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "Anonymous connections" -ForegroundColor Yellow		
	# An adversary can use anonymous connections to gather information about the state of workstations. Information that can be gathered from 
	# anonymous connections (i.e. using the net use command to connect to the IPC$ share) can include lists of users and groups, SIDs for accounts, 
	# lists of shares, workstation policies, operating system versions and patch levels. To reduce this risk, anonymous 
	# connections to workstations should be disabled.

	# Enable insecure guest logons
		Set-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LanmanWorkstation\ -Name AllowInsecureGuestAuth -Value 0
			Write-Host "Enable insecure guest logons is disabled" -ForegroundColor Green	

	# Network access: Allow anonymous SID/Name translation
		Set-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\ -Name TurnOffAnonymousBlock -Value 1
			Write-Host "Allow anonymous SID/Name translation is disabled" -ForegroundColor Green	

	# Network access: Do not allow anonymous enumeration of SAM accounts
		Set-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\ -Name RestrictAnonymousSAM -Value 1
			Write-Host "Do not allow anonymous enumeration of SAM accounts is enabled" -ForegroundColor Green	

	# Network access: Do not allow anonymous enumeration of SAM accounts and shares
		Set-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\ -Name restrictanonymous -Value 1
			Write-Host "Do not allow anonymous enumeration of SAM accounts and shares is enabled" -ForegroundColor Green	

	# Network access: Let Everyone permissions apply to anonymous users
		Set-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\ -Name EveryoneIncludesAnonymous -Value 0
			Write-Host "Let Everyone permissions apply to anonymous users is disabled" -ForegroundColor Green	

	# Network access: Restrict anonymous access to Named Pipes and Shares
		Set-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\ -Name RestrictNullSessAccess -Value 1
			Write-Host "Restrict anonymous access to Named Pipes and Shares is enabled" -ForegroundColor Green	

	# Network access: Do not allow anonymous enumeration of SAM accounts and shares
		Set-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\ -Name RestrictRemoteSAM -Value 'O:BAG:BAD:(A;;RC;;;BA)'
			Write-Host "Do not allow anonymous enumeration of SAM accounts and shares is configured correctly" -ForegroundColor Green	

	# Network security: Allow Local System to use computer identity for NTLM
		Set-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\ -Name UseMachineId -Value 1
			Write-Host "Network security: Allow Local System to use computer identity for NTLM is enabled" -ForegroundColor Green	

	# Allow LocalSystem NULL session fallback is not configured
		Set-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\ -Name allownullsessionfallback -Value 0
			Write-Host "Network security: Allow LocalSystem NULL session fallback is disabled" -ForegroundColor Green			

	# Access this computer from the network
	# Use gpedit.msc and browse to Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\
	# ACSC Recommendation is to set to 'Administrators & Remote Desktop Users'"
		Write-Host "Access this computer from the network - Please Use Group Policy - see script for details" -ForegroundColor White	

	# Deny Access to this computer from the network
	# Use gpedit.msc and browse to Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\. 
	# ACSC Recommendation is to set to 'Guests & NT AUTHORITY\Local Account'"
		Write-Host "Deny Access to this computer from the network - Please Use Group Policy - see script for details" -ForegroundColor White	

#------------------------------------------------------------#
# Antivirus software
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "Antivirus software" -ForegroundColor Yellow		
	# An adversary can develop malicious code to exploit security vulnerabilities in software not detected and remedied by vendors during testing. 
	# As significant time and effort is often involved in the development of functioning and reliable exploits, an adversary will often reuse their 
	# exploits as much as possible before being forced to develop new exploits. To reduce this risk, endpoint security applications with signature-based 
	# antivirus functionality should be implemented. In doing so, signatures should be updated at least on a daily basis.

	# Whilst using signature-based antivirus functionality can assist in reducing risk, they are only effective when a particular piece of malicious 
	# code has already been profiled and signatures are current. An adversary can create variants of known malicious code, or develop new unseen 
	# malicious code, to bypass traditional signature-based detection mechanisms. To reduce this risk, endpoint security applications with host-based 
	# intrusion prevention functionality, or equivalent functionality leveraging cloud-based services, should also be implemented. 
	# In doing so, such functionality should be set at the highest level available.

	# Turn off Windows Defender Antivirus
		Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\" -Name DisableAntiSpyware -Value 0
			Write-Host "Turn off Windows Defender Antivirus is disabled" -ForegroundColor Green

	# Configure local setting override for reporting to Microsoft Active Protection Service (MAPS)
		Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Microsoft Antimalware\SpyNet\' -Name LocalSettingOverrideSpyNetReporting -Value 0
			Write-Host "Configure local setting override for reporting to Microsoft Active Protection Service (MAPS). is disabled" -ForegroundColor Green

	# Configure the 'Block at First Sight' feature
		Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Spynet\' -Name DisableBlockAtFirstSeen -Value 0
			Write-Host "Configure the 'Block at First Sight' feature is enabled" -ForegroundColor Green

	# Join Microsoft Active Protection Service (MAPS)
		Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Microsoft Antimalware\SpyNet\' -Name SpyNetReporting -Value 1
			Write-Host "Join Microsoft Active Protection Service (MAPS) is enabled" -ForegroundColor Green

	# Send file samples when further analysis is required
		Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Spynet\' -Name SubmitSamplesConsent -Value 1
			Write-Host "Send file samples when further analysis is required is enabled" -ForegroundColor Green

	# Configure extended cloud check
		Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\MpEngine\' -Name MpBafsExtendedTimeout -Value 1
			Write-Host "Configure extended cloud check is enabled" -ForegroundColor Green

	# Select cloud protection level
		Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\MpEngine\' -Name MpCloudBlockLevel -Value 1
			Write-Host "Select cloud protection level is enabled" -ForegroundColor Green

	# Configure local setting override for scanning all downloaded files and attachments
		Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\' -Name LocalSettingOverrideDisableIOAVProtection -Value 1
			Write-Host "Configure local setting override for scanning all downloaded files and attachments is enabled" -ForegroundColor Green

	# Turn off real-time protection
		Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\' -Name DisableRealtimeMonitoring -Value 0
			Write-Host "Turn off real-time protection is disabled" -ForegroundColor Green

	# Turn on behavior monitoring
		Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\' -Name DisableBehaviorMonitoring -Value 1
			Write-Host "Turn on behavior monitoring is enabled" -ForegroundColor Green

	# Turn on process scanning whenever real-time protection
		Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Real-Time Protection\' -Name DisableScanOnRealtimeEnable -Value 1
			Write-Host "Turn on process scanning whenever real-time protection is enabled is enabled" -ForegroundColor Green

	# Configure removal of items from Quarantine folder
		Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Quarantine\' -Name PurgeItemsAfterDelay -Value 0
			Write-Host "Configure removal of items from Quarantine folder is disabled" -ForegroundColor Green

	# Allow users to pause scan
		Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Microsoft Antimalware\Scan\' -Name AllowPause -Value 0
			Write-Host "Allow users to pause scan is disabled" -ForegroundColor Green

	# Check for the latest virus and spyware definitions before running a scheduled scan
		Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Microsoft Antimalware\Scan\' -Name CheckForSignaturesBeforeRunningScan -Value 1
			Write-Host "Check for the latest virus and spyware definitions before running a scheduled scan is enabled" -ForegroundColor Green
			
	# Scan archive files
		Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Microsoft Antimalware\Scan\' -Name DisableArchiveScanning -Value 1
			Write-Host "Scan archive files is Enabled" -ForegroundColor Green
			
	# Scan packed executables
		Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Microsoft Antimalware\Scan\' -Name DisablePackedExeScanning -Value 1
			Write-Host "Scan packed executables is enabled" -ForegroundColor Green

	# Scan removable drives
		Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Microsoft Antimalware\Scan\' -Name DisableRemovableDriveScanning -Value 1
			Write-Host "Scan removable drives is enabled" -ForegroundColor Green

	# Turn on e-mail scanning
		Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Microsoft Antimalware\Scan\' -Name DisableEmailScanning -Value 1
			Write-Host "Turn on e-mail scanning is enabled" -ForegroundColor Green

	# Turn on heuristics
		Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Microsoft Antimalware\Scan\' -Name DisableHeuristics -Value 1
			Write-Host "Turn on heuristics is enabled" -ForegroundColor Green

#------------------------------------------------------------#
# Attachment Manager
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "Attachment Manager" -ForegroundColor Yellow		

# The Attachment Manager within Microsoft Windows works in conjunction with applications such as the Microsoft Office suite and Internet Explorer 
# to help protect workstations from attachments that have been received via email or downloaded from the internet. The Attachment Manager 
# classifies files as high, medium or low risk based on the zone they originated from and the type of file. Based on the risk to the workstation, 
# the Attachment Manager will either issue a warning to a user or prevent them from opening a file. If zone information is not preserved, or can be 
# removed, it can allow an adversary to socially engineer a user to bypass protections afforded by the Attachment Manager. To reduce this risk, 
# the Attachment Manager should be configured to preserve and protect zone information for files.

	# Do not preserve zone information in file attachments is disabled
		Set-ItemProperty -Path Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments\ -Name SaveZoneInformation -Value 2
			Write-Host "Do not preserve zone information in file attachments is disabled" -ForegroundColor Green

	# Hide mechanisms to remove zone information is enabled
		Set-ItemProperty -Path Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments\ -Name HideZoneInfoOnProperties -Value 1
			Write-Host "Hide mechanisms to remove zone information is enabled" -ForegroundColor Green

#------------------------------------------------------------#
# Audit event management
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "Audit event management" -ForegroundColor Yellow		

# Failure to capture and analyse security related audit events from workstations can result in intrusions going unnoticed. 
# In addition, the lack of such information can significantly hamper investigations following a security incident. 
# To reduce this risk, security related audit events from workstations should be captured and routinely analysed.

	# Include command line in process creation events is enabled
		Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit\'  -Name ProcessCreationIncludeCmdLine_Enabled -Value 1
			Write-Host "Include command line in process creation events is enabled" -ForegroundColor Green

	# Specify the maximum log file size (KB) for the Application Log is set
		Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Application\'  -Name MaxSize -Value 65536
			Write-Host "Specify the maximum log file size (KB) for the Application Log is set" -ForegroundColor Green

	# Specify the maximum log file size (KB) for the Security Log is set
		Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Security\'  -Name MaxSize -Value 65536
			Write-Host "Specify the maximum log file size (KB) for the Security Log is set" -ForegroundColor Green

	# Specify the maximum log file size (KB) for the System Log is set
		Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\System\'  -Name MaxSize -Value 65536
			Write-Host "Specify the maximum log file size (KB) for the System Log is set" -ForegroundColor Green

	# Specify the maximum log file size (KB) for the Setup Log is set
		Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Setup\'  -Name MaxSize -Value 65536
			Write-Host "Specify the maximum log file size (KB) for the Setup Log is set" -ForegroundColor Green

	# Furthermore, the following Group Policy settings can be implemented to enable a comprehensive auditing strategy.
			Write-Host "Manage Auditing and Security Log is unable to be checked using PowerShell, as the setting is not a registry key. Please check Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment. ACSC Recommendation is to only have 'Administrators' present" -ForegroundColor White
			Write-Host "Audit Credential Validation is unable to be checked using PowerShell, as the setting is not a registry key. Please check Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Account Logon. ACSC Recommendation is to have 'Success and Failure' Present" -ForegroundColor White
			Write-Host "Audit Computer Account Management is unable to be checked using PowerShell, as the setting is not a registry key. ACSC Recommendation is to have 'Success and Failure' Present" -ForegroundColor White
			Write-Host "Audit Other Account Management Events is unable to be checked using PowerShell, as the setting is not a registry key. ACSC Recommendation is to have 'Success and Failure' Present" -ForegroundColor White
			Write-Host "Audit Security Group Management is unable to be checked using PowerShell, as the setting is not a registry key. ACSC Recommendation is to have 'Success and Failure' Present" -ForegroundColor White
			Write-Host "Audit User Account Management is unable to be checked using PowerShell, as the setting is not a registry key. ACSC Recommendation is to have 'Success and Failure' Present" -ForegroundColor White
			Write-Host "Audit PNP Activity is unable to be checked using PowerShell, as the setting is not a registry key. ACSC Recommendation is to have 'Success' Present" -ForegroundColor White
			Write-Host "Audit Process Creation is unable to be checked using PowerShell, as the setting is not a registry key. ACSC Recommendation is to have 'Success' Present" -ForegroundColor White
			Write-Host "Audit Process Termination is unable to be checked using PowerShell, as the setting is not a registry key. ACSC Recommendation is to have 'Success' Present" -ForegroundColor White
			Write-Host "Audit Account Lockout is unable to be checked using PowerShell, as the setting is not a registry key. Please check. ACSC Recommendation is to have 'Success and Failure' Present" -ForegroundColor White
			Write-Host "Audit Group Membership is unable to be checked using PowerShell, as the setting is not a registry key. ACSC Recommendation is to have 'Success' Present" -ForegroundColor White
			Write-Host "Audit Logoff is unable to be checked using PowerShell, as the setting is not a registry key. ACSC Recommendation is to have 'Success' Present" -ForegroundColor White
			Write-Host "Audit Logon is unable to be checked using PowerShell, as the setting is not a registry key. ACSC Recommendation is to have 'Success and Failure' Present" -ForegroundColor White
			Write-Host "Audit Other Logon/Logoff Events is unable to be checked using PowerShell, as the setting is not a registry key. ACSC Recommendation is to have 'Success and Failure' Present" -ForegroundColor White
			Write-Host "Audit Audit Special Logon is unable to be checked using PowerShell, as the setting is not a registry key. ACSC Recommendation is to have 'Success and Failure' Present" -ForegroundColor White
			Write-Host "Audit File Share is unable to be checked using PowerShell, as the setting is not a registry key. ACSC Recommendation is to have 'Success and Failure' Present" -ForegroundColor White
			Write-Host "Audit Kernel Object is unable to be checked using PowerShell, as the setting is not a registry key. ACSC Recommendation is to have 'Success and Failure' Present" -ForegroundColor White
			Write-Host "Audit Other Object Access Events is unable to be checked using PowerShell, as the setting is not a registry key. ACSC Recommendation is to have 'Success and Failure' Present" -ForegroundColor White
			Write-Host "Audit Removable Storage is unable to be checked using PowerShell, as the setting is not a registry key ACSC Recommendation is to have 'Success and Failure' Present" -ForegroundColor White
			Write-Host "Audit Audit Policy Change is unable to be checked using PowerShell, as the setting is not a registry key. ACSC Recommendation is to have 'Success and Failure' Present" -ForegroundColor White
			Write-Host "Audit Authentication Policy Change is unable to be checked using PowerShell, as the setting is not a registry key. ACSC Recommendation is to have 'Success' Present" -ForegroundColor White
			Write-Host "Audit Authorization Policy Change is unable to be checked using PowerShell, as the setting is not a registry key. ACSC Recommendation is to have 'Success' Present" -ForegroundColor White
			Write-Host "Audit Sensitive Privilege Use is unable to be checked using PowerShell, as the setting is not a registry key. Please check Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Privilege Use. ACSC Recommendation is to have 'Success and Failure' Present" -ForegroundColor White
			Write-Host "Audit IPsec Driver is unable to be checked using PowerShell, as the setting is not a registry key. ACSC Recommendation is to have 'Success and Failure' Present" -ForegroundColor White
			Write-Host "Audit Other System Events is unable to be checked using PowerShell, as the setting is not a registry key. ACSC Recommendation is to have 'Success and Failure' Present" -ForegroundColor White
			Write-Host "Audit Security State Change is unable to be checked using PowerShell, as the setting is not a registry key. ACSC Recommendation is to have 'Success' Present" -ForegroundColor White
			Write-Host "Audit Security System Extension is unable to be checked using PowerShell, as the setting is not a registry key. ACSC Recommendation is to have 'Success and Failure' Present" -ForegroundColor White
			Write-Host "Audit System Integrity is unable to be checked using PowerShell, as the setting is not a registry key. ACSC Recommendation is to have 'Success and Failure' Present" -ForegroundColor White

	# Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings
		Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\'  -Name SCENoApplyLegacyAuditPolicy -Value 1
			Write-Host "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings is enabled" -ForegroundColor Green

#------------------------------------------------------------#
# Autoplay and AutoRun
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "Autoplay and AutoRun" -ForegroundColor Yellow		

# When enabled, Autoplay will automatically begin reading from a drive or media source as soon as it is used with a workstation, 
# while AutoRun commands, generally in an autorun.inf file on the media, can be used to automatically execute any file on the media 
# without user interaction. This functionality can be exploited by an adversary to automatically execute malicious code. 
# To reduce this risk, Autoplay and AutoRun functionality should be disabled.

	# Disallow Autoplay for non-volume devices
		Set-ItemProperty -Path  'Registry::HKLM\Software\Policies\Microsoft\Windows\Explorer\' -Name NoAutoplayfornonVolume -Value 1
			Write-Host "Disallow Autoplay for non-volume devices is enabled in Local Machine GP" -ForegroundColor Green
		Set-ItemProperty -Path  'Registry::HKCU\Software\Policies\Microsoft\Windows\Explorer\' -Name NoAutoplayfornonVolume -Value 1
			Write-Host "Disallow Autoplay for non-volume devices is enabled in User GP" -ForegroundColor Green

	# Set the default behavior for AutoRun
		Set-ItemProperty -Path  'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\' -Name NoAutorun -Value 1
			Write-Host "Set the default behavior for AutoRun is enabled in Local Machine GP" -ForegroundColor Green
		Set-ItemProperty -Path  'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\' -Name NoAutorun -Value 1
			Write-Host "Set the default behavior for AutoRun is enabled in User GP" -ForegroundColor Green
			
	# Turn off Autoplay
		Set-ItemProperty -Path  'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\' -Name NoDriveTypeAutoRun -Value 255
			Write-Host "Turn off Autoplay is enabled in Local Machine GP" -ForegroundColor Green
		Set-ItemProperty -Path  'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\' -Name NoDriveTypeAutoRun -Value 255
			Write-Host "Turn off Autoplay is enabled in User GP" -ForegroundColor Green

#------------------------------------------------------------#
# BIOS and UEFI passwords
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "Autoplay and AutoRun" -ForegroundColor Yellow	

# An adversary with access to a workstation’s Basic Input/Output System (BIOS) or UEFI can modify the hardware 
# configuration of the workstation to introduce attack vectors or weaken security functionality within the workstation’s 
# operating system. This can include disabling security functionality in the CPU, modifying allowed boot devices and 
# enabling insecure communications interfaces such as FireWire and Thunderbolt. To reduce this risk, strong BIOS and 
# UEFI passwords should be used for all workstations to prevent unauthorised access.

		Write-Host "Unable to confirm that a BIOS password is set via PowerShell. Please manually check if a BIOS password is set (if applicable)" -ForegroundColor White

#------------------------------------------------------------#
# Boot devices
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "Boot devices" -ForegroundColor Yellow	

# By default, workstations are often configured to boot from optical media, or even USB media, in preference to hard drives. 
# An adversary with physical access to such workstations can boot from their own media in order to gain access to the content 
# of the hard drives. With this access, an adversary can reset local user account passwords or gain access to the local SAM 
# database to steal password hashes for offline brute force cracking attempts. To reduce this risk, workstations should be 
# restricted to only booting from the designated primary system drive.		

		Write-Host "Please manually check to ensure that the hard disk of this device is the primary boot device and the machine is unable to be booted off removable media (if applicable)" -ForegroundColor White

#------------------------------------------------------------#
# Bridging networks
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "Bridging networks" -ForegroundColor Yellow	
		
# When workstations have multiple network interfaces, such as an Ethernet interface and a wireless interface, 
# it is possible to establish a bridge between the connected networks. For example, when using an Ethernet interface 
# to connect to an organisation’s wired network and a wireless interface to connect to another non-organisation 
# controlled network such as a public wireless hotspot. When bridges are created between such networks an adversary 
# can directly access the wired network from the wireless network to extract sensitive information. 
# To reduce this risk, the ability to install and configure network bridges between different networks should be disabled. 
# This won’t prevent an adversary from compromising a workstation via the wireless network and then using malicious 
# software as a medium to indirectly access the wired network. This can only be prevented by manually disabling 
# all wireless interfaces when connecting to wired networks.		
		
	# Prohibit installation and configuration of Network Bridge on your DNS domain network
		Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Network Connections\'  -Name NC_AllowNetBridge_NLA -Value 0
			Write-Host "Prohibit installation and configuration of Network Bridge on your DNS domain network is enabled" -ForegroundColor Green

	# Prohibit use of Internet Connection Sharing on your DNS domain network
		Set-ItemProperty -Path  'Registry:Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Network Connections\'  -Name NC_ShowSharedAccessUI -Value 0
			Write-Host "Prohibit use of Internet Connection Sharing on your DNS domain network is enabled" -ForegroundColor Green

	# Route all traffic through the internal network
		Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\TCPIP\v6Transition\'  -Name Force_Tunneling -Value 'Enabled'
			Write-Host "Route all traffic through the internal network is enabled" -ForegroundColor Green

	# Prohibit connection to non-domain networks when connected to domain authenticated network
		Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\'  -Name fBlockNonDomain -Value 1
			Write-Host "Prohibit connection to non-domain networks when connected to domain authenticated network is enabled" -ForegroundColor Green

#------------------------------------------------------------#
# Built-in guest accounts
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "Built-in guest accounts" -ForegroundColor Yellow	

# When built-in guest accounts are used, it can allow an adversary to log onto a workstation over the network 
# without first needing to compromise legitimate user credentials. To reduce this risk, built-in guest accounts should be disabled.		

	# Disable guest account
		Disable-LocalUser - Name "Guest"
			Write-Host "The local guest account is disabled" -ForegroundColor Green

#------------------------------------------------------------#
# CD burner access
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "CD burner access" -ForegroundColor Yellow	
		
# If CD burning functionality is enabled, and CD burners are installed in workstations, an adversary may attempt to steal sensitive 
# information by burning it to CD. To reduce this risk, users should not have access to CD burning functionality except when explicitly required.
# The following Group Policy setting can be implemented to prevent access to CD burning functionality, although as this 
# Group Policy setting only prevents access to native CD burning functionality in Microsoft Windows, users should also be 
# prevented from installing third party CD burning applications. Alternatively, CD readers can be used in workstations instead of CD burners.		
		
	# Remove CD Burning features
		Set-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\'  -Name NoCDBurning -Type DWord -Value 1
			Write-Host "Remove CD Burning features is enabled" -ForegroundColor Green

#------------------------------------------------------------#
# Centralised audit event logging
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "Centralised audit event logging" -ForegroundColor Yellow	
		
# Storing audit event logs on workstations poses a risk that an adversary could attempt to modify or delete these logs during 
# an intrusion to cover their tracks. In addition, failure to conduct centralised audit event logging will reduce the visibility 
# of audit events across all workstations, prevent the correlation of audit events and increase the complexity of any investigations 
# after security incidents. To reduce this risk, audit event logs from workstations should be transferred to a secure central logging server.

Write-Host "Centralised Audit Event Logging is unable to be checked with PowerShell. Ensure the organisation is using Centralised Event Logging, please confirm events from endpoint computers are being sent to a central location." -ForegroundColor White

#------------------------------------------------------------#
# Command Prompt
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "Centralised audit event logging" -ForegroundColor Yellow	

# An adversary who gains access to a workstation can use the Command Prompt to execute in-built Microsoft Windows tools 
# to gather information about the workstation or domain as well as schedule malicious code to execute on other workstations 
# on the network. To reduce this risk, users should not have Command Prompt access or the ability to execute batch files 
# and scripts. Should a legitimate business requirement exist to allow users to execute batch files (e.g. cmd and bat files); 
# run logon, logoff, startup or shutdown batch file scripts; or use Remote Desktop Services, this risk will need to be accepted.

	# Prevent access to the command prompt
		Set-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\System\'  -Name DisableCMD - Value 1
			Write-Host "Prevent access to the command prompt is enabled" -ForegroundColor Green

#------------------------------------------------------------#
# Direct Memory Access
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "Direct Memory Access" -ForegroundColor Yellow	

# An adversary with physical access to a workstation may be able to use a bootable CD/DVD or USB media to load 
# their own operating environment. From this environment, they can access the local file system to gain access 
# to sensitive information or the SAM database to access password hashes. In addition, an adversary that gains 
# access to a stolen or unsanitised hard drive, or other removable media, will be to recover its contents when 
# connected to another machine on which they have administrative access and can take ownership of files. To 
# reduce this risk, AES-based full disk encryption should be used to protect the contents of hard drives from 
# unauthorised access. The use of full disk encryption may also contribute to streamlining media sanitisation during decommissioning processes.

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\'  -Name DenyDeviceIDs -Value 1
Write-Host "Prevent installation of devices that match any of these device IDs is enabled" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\'  -Name DenyDeviceIDsRetroactive -Value 1
Write-Host "Prevent installation of devices that match any of these device IDs (retroactively) is enabled" -ForegroundColor Green

Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs\" -Name 1 -Value 'PCI\CC_0C0A'
Write-Host "PCI\CC_0C0A is included on the banned device list to prevent DMA installations" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\'  -Name DenyDeviceClasses -Value 1
Write-Host "Prevent installation of devices using drivers that match these device setup classes is enabled" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\'  -Name DenyDeviceClassesRetroactive -Value 1
Write-Host "Prevent installation of devices using drivers that match these device setup classes (retroactively) is enabled" -ForegroundColor Green

Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses\" -Name 1 -Value 'd48179be-ec20-11d1-b6b8-00c04fa372a7'
Write-Host "d48179be-ec20-11d1-b6b8-00c04fa372a7 is included on the banned device list to prevent DMA installations" -ForegroundColor Green

#------------------------------------------------------------#
# Drive encryption
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "Drive encryption" -ForegroundColor Yellow	
# 
# An adversary with physical access to a workstation may be able to use a bootable CD/DVD or USB 
# media to load their own operating environment. From this environment, they can access the local 
# file system to gain access to sensitive information or the SAM database to access password hashes. 
# In addition, an adversary that gains access to a stolen or unsanitised hard drive, or other 
# removable media, will be to recover its contents when connected to another machine on which they 
# have administrative access and can take ownership of files. To reduce this risk, AES-based full 
# disk encryption should be used to protect the contents of hard drives from unauthorised access. 
# The use of full disk encryption may also contribute to streamlining media sanitisation 
# during decommissioning processes.
#
#See external Bitlocker script >>> 
#

#------------------------------------------------------------#
# Endpoint Device Control
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "Endpoint Device Control" -ForegroundColor Yellow	

# An adversary with physical access to a workstation may attempt to connect unauthorised USB media or other 
# devices with mass storage functionality (e.g. smartphones, digital music players or cameras) to facilitate 
# malicious code infections or the unauthorised copying of sensitive information. To reduce this risk, 
# endpoint device control functionality should be appropriately implemented to control the use of all removable storage devices.

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\RemovableStorageDevices\'  -Name Deny_All -Value 1
Write-Host "All Removable Storage classes: Deny all access is enabled in local machine group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKCU\Software\Policies\Microsoft\Windows\RemovableStorageDevices\'  -Name Deny_All -Value 1
Write-Host "All Removable Storage classes: Deny all access is enabled in user group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\RemovableStorageDevices\53f56308-b6bf-11d0-94f2-00a0c91efb8b\'  -Name Deny_Execute -Value 1
Write-Host "CD and DVD: Deny execute access is enabled in local machine group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\RemovableStorageDevices\53f56308-b6bf-11d0-94f2-00a0c91efb8b\'  -Name Deny_Read -Value 0
Write-Host "CD and DVD: Deny read access is disabled in local machine group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\RemovableStorageDevices\53f56308-b6bf-11d0-94f2-00a0c91efb8b\'  -Name Deny_Write -Value 1
Write-Host "CD and DVD: Deny write access is enabled in local machine group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKCU\Software\Policies\Microsoft\Windows\RemovableStorageDevices\53f56308-b6bf-11d0-94f2-00a0c91efb8b\'  -Name Deny_Read -Value 0
Write-Host "CD and DVD: Deny read access is disabled in user group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKCU\Software\Policies\Microsoft\Windows\RemovableStorageDevices\53f56308-b6bf-11d0-94f2-00a0c91efb8b\'  -Name Deny_Write -Value 1
Write-Host "CD and DVD: Deny write access is enabled in user group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKLM\Software\Policies\Microsoft\Windows\RemovableStorageDevices\Custom\Deny_Read\' -Name Deny_Read -Value 0
Write-Host "Custom Classes: Deny read access is disabled in local machine group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKLM\Software\Policies\Microsoft\Windows\RemovableStorageDevices\Custom\Deny_Write\' -Name Deny_Write -Value 1
Write-Host "Custom Classes: Deny write access is enabled in local machine group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\RemovableStorageDevices\Custom\Deny_Read\' -Name Deny_Read -Value 0
Write-Host "Custom Classes: Deny read access is disabled in user group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\RemovableStorageDevices\Custom\Deny_Write\'  -Name Deny_Write -Value 1
Write-Host "Custom Classes: Deny write access is enabled in user group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\RemovableStorageDevices\53f56311-b6bf-11d0-94f2-00a0c91efb8b\'  -Name Deny_Execute -Value 1
Write-Host "Floppy Drives: Deny execute access is enabled in local machine group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKLM\Software\Policies\Microsoft\Windows\RemovableStorageDevices\53f56311-b6bf-11d0-94f2-00a0c91efb8b\'  -Name Deny_Read -Value 0
Write-Host "Floppy Drives: Deny read access is disabled in local machine group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKLM\Software\Policies\Microsoft\Windows\RemovableStorageDevices\53f56311-b6bf-11d0-94f2-00a0c91efb8b\'  -Name Deny_Write -Value 1
Write-Host "Floppy Drives: Deny write access is enabled in local machine group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\RemovableStorageDevices\53f56311-b6bf-11d0-94f2-00a0c91efb8b\'  -Name Deny_Read -Value 0
Write-Host "Floppy Drives: Deny read access is disabled in user group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\RemovableStorageDevices\53f56311-b6bf-11d0-94f2-00a0c91efb8b\'  -Name Deny_Write -Value 1
Write-Host "Floppy Drives: Deny write access is enabled in user group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\RemovableStorageDevices\53f5630d-b6bf-11d0-94f2-00a0c91efb8b\'  -Name Deny_Execute -Value 1
Write-Host "Removable Disks: Deny execute access is enabled in local machine group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKLM\Software\Policies\Microsoft\Windows\RemovableStorageDevices\53f5630d-b6bf-11d0-94f2-00a0c91efb8b\'  -Name Deny_Read -Value 0
Write-Host "Removable Disks: Deny read access is disabled in local machine group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKLM\Software\Policies\Microsoft\Windows\RemovableStorageDevices\53f5630d-b6bf-11d0-94f2-00a0c91efb8b\'  -Name Deny_Write -Value 1
Write-Host "Removable Disks: Deny write access is enabled in local machine group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\RemovableStorageDevices\53f5630d-b6bf-11d0-94f2-00a0c91efb8b\'  -Name Deny_Read -Value 0
Write-Host "Removable Disks: Deny read access is disabled in user group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\RemovableStorageDevices\53f5630d-b6bf-11d0-94f2-00a0c91efb8b\'  -Name Deny_Write -Value 1
Write-Host "Removable Disks: Deny write access is enabled in user group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\RemovableStorageDevices\53f5630b-b6bf-11d0-94f2-00a0c91efb8b\'  -Name Deny_Execute -Value 1
Write-Host "Tape Drives: Deny execute access is enabled in local machine group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\RemovableStorageDevices\53f5630b-b6bf-11d0-94f2-00a0c91efb8b\'  -Name Deny_Read -Value 0
Write-Host "Tape Drives: Deny read access is disabled in user group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\RemovableStorageDevices\53f5630b-b6bf-11d0-94f2-00a0c91efb8b\'  -Name Deny_Write -Value 1
Write-Host "Tape Drives: Deny write access is enabled in user group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKLM\Software\Policies\Microsoft\Windows\RemovableStorageDevices\53f5630b-b6bf-11d0-94f2-00a0c91efb8b\'  -Name Deny_Read -Value 0
Write-Host "Tape Drives: Deny read access is disabled in local machine group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKLM\Software\Policies\Microsoft\Windows\RemovableStorageDevices\53f5630b-b6bf-11d0-94f2-00a0c91efb8b\'  -Name Deny_Write -Value 1
Write-Host "Tape Drives: Deny write access is enabled in local machine group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKLM\Software\Policies\Microsoft\Windows\RemovableStorageDevices\6AC27878-A6FA-4155-BA85-F98F491D4F33\'  -Name Deny_Read -Value 0
Set-ItemProperty -Path  'Registry::HKLM\Software\Policies\Microsoft\Windows\RemovableStorageDevices\F33FDC04-D1AC-4E8E-9A30-19BBD4B108AE\'  -Name Deny_Read -Value 0
Write-Host "WPD Devices: Deny read access is disabled in local machine group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKLM\Software\Policies\Microsoft\Windows\RemovableStorageDevices\6AC27878-A6FA-4155-BA85-F98F491D4F33\'  -Name Deny_Write -Value 1
Set-ItemProperty -Path  'Registry::HKLM\Software\Policies\Microsoft\Windows\RemovableStorageDevices\F33FDC04-D1AC-4E8E-9A30-19BBD4B108AE\'  -Name Deny_Write -Value 1
Write-Host "WPD Devices: Deny write access is enabled in local machine group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKCU\Software\Policies\Microsoft\Windows\RemovableStorageDevices\6AC27878-A6FA-4155-BA85-F98F491D4F33\'  -Name Deny_Read -Value 0
Set-ItemProperty -Path  'Registry::HKCU\Software\Policies\Microsoft\Windows\RemovableStorageDevices\F33FDC04-D1AC-4E8E-9A30-19BBD4B108AE\'  -Name Deny_Read -Value 0
Write-Host "WPD Devices: Deny read access is disabled in user group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKCU\Software\Policies\Microsoft\Windows\RemovableStorageDevices\6AC27878-A6FA-4155-BA85-F98F491D4F33\'  -Name Deny_Write -Value 1
Set-ItemProperty -Path  'Registry::HKCU\Software\Policies\Microsoft\Windows\RemovableStorageDevices\F33FDC04-D1AC-4E8E-9A30-19BBD4B108AE\'  -Name Deny_Write -Value 1
Write-Host "WPD Devices: Deny write access is enabled in user  group policy" -ForegroundColor Green

#------------------------------------------------------------#
# File and Print Sharing
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "File and Print Sharing" -ForegroundColor Yellow	

# Users sharing files from their workstations can result in a lack of appropriate access controls 
# being applied to sensitive information and the potential for the propagation of malicious code 
# should file shares have read/write access. To reduce this risk, local file and print sharing 
# should be disabled. Ideally, sensitive information should be centrally managed (e.g. on a network 
# share with appropriate access controls). Disabling file and print sharing will not 
# affect a user’s ability to access shared drives and printers on a network.

# Prevent the computer from joining a homegroup
Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\HomeGroup\'  -Name DisableHomeGroup -Value 1
Write-Host "Prevent the computer from joining a homegroup is enabled" -ForegroundColor Green

# Prevent users from sharing files within their profile
Set-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\'  -Name NoInplaceSharing -Value 1
Write-Host "Prevent users from sharing files within their profile is enabled" -ForegroundColor Green

#------------------------------------------------------------#
# Group Policy Processing
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "Group Policy Processing" -ForegroundColor Yellow	

# Relying on users to set Group Policy settings for their workstations creates the potential 
# for users to inadvertently misconfigure or disable security functionality without consideration 
# of the impact on the security posture of the workstation. Alternatively, an adversary could 
# exploit this to disable any Local Group Policy settings that are hampering their efforts to 
# extract sensitive information. To reduce this risk, all audit, user rights and security related 
# Group Policy settings should be specified for workstations at an organisational unit or 
# domain level. To ensure these policies aren’t weakened, support for Local Group 
# Policy settings should also be disabled.

# Configure registry policy processing
Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Group Policy\35378EAC-683F-11D2-A89A-00C04FBBCFA2\'  -Name NoGPOListChanges -Value 0
Write-Host "Configure registry policy processing is enabled" -ForegroundColor Green
Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Group Policy\827D319E-6EAC-11D2-A4EA-00C04F79F83A\'  -Name NoGPOListChanges -Value 0
Write-Host "Configure security policy processing is enabled" -ForegroundColor Green

# Turn off background refresh of Group Policy
Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\'  -Name DisableBkGndGroupPolicy -Value 0
Write-Host "Turn off background refresh of Group Policy is disabled" -ForegroundColor Green
Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System\'  -Name DisableLGPOProcessing -Value 1
Write-Host "Turn off Local Group Policy Objects processing is enabled" -ForegroundColor Green

#------------------------------------------------------------#
# Installing applications and drivers
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "Installing applications and drivers" -ForegroundColor Yellow	
		
# While the ability to install applications may be a business requirement for users, this privilege 
# can be exploited by an adversary. An adversary can email a malicious application, or host a malicious 
# application on a compromised website, and use social engineering techniques to convince users into 
# installing the application on their workstation. Even if privileged access is required to install 
# applications, users will use their privileged access if they believe, or can be convinced that, 
# the requirement to install the application is legitimate. Additionally, if applications are 
# configured to install using elevated privileges, an adversary can exploit this by creating a 
# Windows Installer installation package to create a new account that belongs to the local built-in 
# administrators group or to install a malicious application. Alternatively, an adversary may attempt 
# to install drivers that are not relevant to a system in order to introduce security vulnerabilities. 
# To reduce this risk, all application and driver installations should be strictly controlled.

# Configure Windows Defender SmartScreen
Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System\'  -Name EnableSmartScreen -Value 1
Write-Host "Configure Windows Defender SmartScreen is enabled" -ForegroundColor Green

# Windows Defender SmartScreen is set to Warn and Prevent Bypass
Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System\'  -Name ShellSmartScreenLevel -Value 'Block'
Write-Host "Windows Defender SmartScreen is set to Warn and Prevent Bypass" -ForegroundColor Green

# Allow user control over installs
Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer\'  -Name EnableUserControl -Value 0
Write-Host "Allow user control over installs is disabled" -ForegroundColor Green

# Always install with elevated privileges is disabled in local machine policy
Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer\'  -Name AlwaysInstallElevated -Value 0
Write-Host "Always install with elevated privileges is disabled in local machine policy" -ForegroundColor Green

# Always install with elevated privileges is disabled in user policy
Set-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer\'  -Name AlwaysInstallElevated -Value 0
Write-Host "Always install with elevated privileges is disabled in user policy" -ForegroundColor Green

#------------------------------------------------------------#
# Legacy and run once lists
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "Legacy and run once lists" -ForegroundColor Yellow	

# Once malicious code has been copied to a workstation, an adversary with registry access can 
# remotely schedule it to execute (i.e. using the run once list) or to automatically execute each 
# time Microsoft Windows starts (i.e. using the legacy run list). To reduce this risk, legacy 
# and run once lists should be disabled. This may interfere with the operation of legitimate 
# applications that need to automatically execute each time Microsoft Windows starts. In such 
# cases, the Run these programs at user logon Group Policy setting can be used to perform the
# same function in a more secure manner when defined at a domain level; however, if not used 
# this Group Policy setting should be disabled rather than left in its default undefined state.

# Do not process the legacy run list is enabled
Set-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\'  -Name DisableCurrentUserRun -Value 1
Write-Host "Do not process the legacy run list is enabled" -ForegroundColor Green

# Do not process the run once list is enabled
Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\'  -Name DisableLocalMachineRunOnce -Value 1
Write-Host "Do not process the run once list is enabled" -ForegroundColor Green

# Run These Programs At User Logon is disabled, no run keys are set
# Set-ItemProperty -Path "Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\"
# Set-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\" 
#    Write-Host "Run These Programs At User Logon is disabled, no run keys are set" -ForegroundColor Green

#------------------------------------------------------------#
# Microsoft accounts
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "Microsoft accounts" -ForegroundColor Yellow

# A feature of Microsoft Windows 10 is the ability to link Microsoft accounts (formerly Windows Live IDs) 
# to local or domain accounts. When this occurs, a user’s settings and files are stored in the cloud using 
# OneDrive rather than locally or on a domain controller. While this may have the benefit of allowing users 
# to access their settings and files from any workstation (e.g. corporate workstation, home PC, internet cafe) 
# it can also pose a risk to an organisation as they lose control over where sensitive information may be 
# accessed from. To reduce this risk, users should not link Microsoft accounts with local or domain accounts.

# Block all consumer Microsoft account user authentication
Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\MicrosoftAccount\'  -Name DisableUserAuth -Value 1
Write-Host "Block all consumer Microsoft account user authentication is enabled" -ForegroundColor Green

# Prevent the usage of OneDrive for file storage
Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\OneDrive\'  -Name DisableFileSyncNGSC -Value 1
Write-Host "Prevent the usage of OneDrive for file storage is enabled" -ForegroundColor Green

# Accounts: Block Microsoft accounts
Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'  -Name NoConnectedUse -Value 3
Write-Host "Accounts: Block Microsoft accounts is enabled" -ForegroundColor Green

#------------------------------------------------------------#
# MSS settings
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "MSS settings" -ForegroundColor Yellow

# MSS settings are registry values previously identified by Microsoft security experts that can be used for 
# increased security. While many of these registry values are no longer applicable in modern versions of 
# Microsoft Windows, some still provide a security benefit. By failing to specify these MSS settings, an 
# adversary may be able to exploit weaknesses in a workstation’s security posture to gain access to sensitive 
# information. To reduce this risk, MSS settings that are still relevant to modern versions of Microsoft 
# Windows should be specified using Group Policy settings.

# The Group Policy Administrative Templates for MSS settings are available from the Microsoft Security 
# Guidance blog. The ADMX and ADML files can be placed in %SystemDrive%\Windows\SYSVOL\domain\Policies\PolicyDefinitions 
# on the Domain Controller and they will automatically be loaded in the Group Policy Management Editor.

# (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)
Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters\'  -Name DisableIPSourceRouting -Value 2
Write-Host "MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing) is set to Highest protection, source routing is completely disabled " -ForegroundColor Green

# (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing) is set to Highest protection, source routing is completely disabled
Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip6\Parameters\'  -Name DisableIPSourceRouting -Value 2
Write-Host "MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing) is set to Highest protection, source routing is completely disabled " -ForegroundColor Green

# (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes is disabled
Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters\'  -Name EnableICMPRedirect -Value 0
Write-Host "MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes is disabled" -ForegroundColor Green

# (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers is enabled
Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netbt\Parameters\'  -Name NoNameReleaseOnDemand -Value 1
Write-Host "MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers is enabled" -ForegroundColor Green

#------------------------------------------------------------#
# NetBIOS over TCP/IP
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "NetBIOS over TCP/IP" -ForegroundColor Yellow

# NetBIOS over TCP/IP facilitates a number of intrusion methods. To reduce this risk, NetBIOS over TCP/IP 
# should be disabled. As NetBIOS over TCP/IP is only used to support legacy Microsoft Windows operating 
# systems, such as those prior to Microsoft Windows 2000, there shouldn’t be a business requirement for 
# its use except in very rare circumstances. NetBIOS over TCP/IP can be disabled by setting the NetBIOS 
# settings under the IPv4 WINS settings on each network interface to Disable NetBIOS over TCP/IP. 
# NetBIOS over TCP/IP is not supported by IPv6.

Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\tcpip*' -Name NetbiosOptions -Value 2
Write-Host "NetBIOS over TCP/IP is disabled" -ForegroundColor Green

#------------------------------------------------------------#
# Network authentication
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "Network authentication" -ForegroundColor Yellow

# Using insecure network authentication methods may allow an adversary to gain unauthorised access to 
# network traffic and services. To reduce this risk, only secure network authentication methods, 
# ideally Kerberos, should be used for network authentication.

# Configure encryption types allowed for Kerberos is set to AES128_HMAC_SHA1 and AES256_HMAC_SHA1
Set-ItemProperty -Path  'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\'  -Name SupportedEncryptionTypes -Value 24
Write-Host "Configure encryption types allowed for Kerberos is set to AES128_HMAC_SHA1 and AES256_HMAC_SHA1" -ForegroundColor Green

# Network security: LAN Manager authentication level - Send NTLMv2 response only. Refuse LM & NTLM
Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\'  -Name LMCompatibilityLevel -Value 5
Write-Host "LAN Manager authentication level is set to Send NTLMv2 response only & refuse LM & NTLM" -ForegroundColor Green

# Minimum session security for NTLM SSP based (including secure RPC) clients is set to Require NTLMv2 session security & Require 128-bit encryption
Set-ItemProperty -Path  'Registry::HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0\'  -Name NTLMMinClientSec -Value 537395200
Write-Host "Minimum session security for NTLM SSP based (including secure RPC) clients is set to Require NTLMv2 session security & Require 128-bit encryption" -ForegroundColor Green

# Minimum session security for NTLM SSP based (including secure RPC) servers is set to Require NTLMv2 session security and Require 128-bit encryption
Set-ItemProperty -Path  'Registry::HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0\'  -Name NTLMMinServerSec -Value 537395200
Write-Host "Minimum session security for NTLM SSP based (including secure RPC) servers is set to Require NTLMv2 session security and Require 128-bit encryption" -ForegroundColor Green

#------------------------------------------------------------#
# NoLMHash policy
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "NoLMHash policy" -ForegroundColor Yellow

# When Microsoft Windows hashes a password that is less than 15 characters, it stores both a LAN 
# Manager hash (LM hash) and Windows NT hash (NT hash) in the local SAM database for local accounts, 
# or in Activity Directory for domain accounts. The LM hash is significantly weaker than the NT hash 
# and can easily be brute forced. To reduce this risk, the NoLMHash Policy should be implemented on 
# all workstations and domain controllers. As the LM hash is designed for authentication of legacy 
# Microsoft Windows operating systems, such as those prior to Microsoft Windows 2000, there shouldn’t 
# be a business requirement for its use except in very rare circumstances.

# Do not store LAN Manager hash value on next password change is enabled
Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\'  -Name noLMHash -Value 1
Write-Host "Network security: Do not store LAN Manager hash value on next password change is enabled" -ForegroundColor Green

#------------------------------------------------------------#
# Operating system functionality
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "Operating system functionality" -ForegroundColor Yellow

# Leaving unneeded functionality in Microsoft Windows enabled can provide greater opportunities for 
# potentially vulnerable or misconfigured functionality to be exploited by an adversary. To reduce 
# this risk, unneeded functionality in Microsoft Windows should be disabled or removed.

#$numberofservices = (Get-Service | Measure-Object).Count
#$numberofdisabledservices = (Get-WmiObject Win32_Service | Where-Object $_.StartMode -eq 'Disabled').count
#If ($numberofdisabledservices -eq $null)
#elseif ($numberofdisabledservices -le '30')
#elseif($numberofdisabledservices -gt '30')
#Write-Host "There are $numberofservices services present on this machine and $numberofdisabledservices have been disabled. This incidicates that reduction in operating system functionality has likely been performed." -ForegroundColor Green

#------------------------------------------------------------#
# Password and logon authentication policy
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "Password and logon authentication policy" -ForegroundColor Yellow

# The use of weak passwords, such as eight character passwords with no complexity, can allow them 
# to be brute forced within minutes using applications freely available on the web. 
# To reduce this risk, a secure password policy should be implemented.

# Turn off picture password sign-in
Set-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System\ -Name BlockDomainPicturePassword -Value 1
Write-Host "Turn off picture password sign-in is enabled" -ForegroundColor Green

#Check: Turn on convenience PIN sign-in
Set-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System\ -Name AllowDomainPINLogon -Value 0
Write-Host "Turn on convenience PIN sign-in is disabled" -ForegroundColor Green    

# Store passwords using reversible encryption
# Computer Configuration\Windows Settings\Security Settings\Account Policies\Password Policy\Store passwords using reversible encryption

#Check: Limit local account use of blank passwords to console logon only
Set-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\ -Name LimitBlankPasswordUse -Value 1
Write-Host "Limit local account use of blank passwords to console logon only is enabled" -ForegroundColor Green

#------------------------------------------------------------#
# Password and logon authentication policy
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "Password and logon authentication policy" -ForegroundColor Yellow
		
# One method of reducing power usage by workstations is to enter a sleep, hibernation or hybrid sleep state 
# after a pre-defined period of inactivity. When a workstation enters a sleep state it maintains the contents 
# of memory while powering down the rest of the workstation; with hibernation or hybrid sleep, it writes the 
# contents of memory to the hard drive in a hibernation file (hiberfil.sys) and powers down the rest of the 
# workstation. When this occurs, sensitive information such as encryption keys could either be retained in 
# memory or written to the hard drive in a hibernation file. An adversary with physical access to the workstation 
# and either the memory or hard drive can recover the sensitive information using forensic techniques. 
# To reduce this risk, sleep, hibernation and hybrid sleep states should be disabled.

# Allow standby states (S1-S3) when sleeping (on battery) is disabled
Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab\'  -Name DCSettingIndex -Value 0
Write-Host "Allow standby states (S1-S3) when sleeping (on battery) is disabled" -ForegroundColor Green

# Allow standby states (S1-S3) when sleeping (plugged in) is disabled
Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab\'  -Name ACSettingIndex -Value 0
Write-Host "Allow standby states (S1-S3) when sleeping (plugged in) is disabled" -ForegroundColor Green

# Require a password when a computer wakes (on battery) is enabled
Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\'  -Name DCSettingIndex -Value 1
Write-Host "Require a password when a computer wakes (on battery) is enabled" -ForegroundColor Green

# Require a password when a computer wakes (plugged in) is enabled
Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\'  -Name ACSettingIndex -Value 1
Write-Host "Require a password when a computer wakes (plugged in) is enabled" -ForegroundColor Green

# Specify the system hibernate timeout (on battery) is enabled and set to 0 seconds
Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\9D7815A6-7EE4-497E-8888-515A05F02364\'  -Name DCSettingIndex -Value 0
Write-Host "Specify the system hibernate timeout (on battery) is enabled and set to 0 seconds" -ForegroundColor Green

# Specify the system hibernate timeout (plugged in) is enabled and set to 0 seconds
Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\9D7815A6-7EE4-497E-8888-515A05F02364\'  -Name ACSettingIndex -Value 0
Write-Host "Specify the system hibernate timeout (plugged in) is enabled and set to 0 seconds" -ForegroundColor Green

# Specify the system sleep timeout (on battery) is enabled and set to 0 seconds
Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\29F6C1DB-86DA-48C5-9FDB-F2B67B1F44DA\'  -Name DCSettingIndex -Value 0
Write-Host "Specify the system sleep timeout (on battery) is enabled and set to 0 seconds" -ForegroundColor Green

# Specify the system sleep timeout (plugged in) is enabled and set to 0 seconds
Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\29F6C1DB-86DA-48C5-9FDB-F2B67B1F44DA\'  -Name ACSettingIndex -Value 0
Write-Host "Specify the system sleep timeout (plugged in) is enabled and set to 0 seconds" -ForegroundColor Green

# Specify the unattended sleep timeout (on battery) is enabled and set to 0 seconds
Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\7bc4a2f9-d8fc-4469-b07b-33eb785aaca0\'  -Name DCSettingIndex -Value 0
Write-Host "Specify the unattended sleep timeout (on battery) is enabled and set to 0 seconds" -ForegroundColor Green

# Specify the unattended sleep timeout (plugged in) is enabled
Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\7bc4a2f9-d8fc-4469-b07b-33eb785aaca0\'  -Name ACSettingIndex -Value 0
Write-Host "Specify the unattended sleep timeout (plugged in) is enabled" -ForegroundColor Green

# Turn off hybrid sleep (on battery) is enabled
Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\94ac6d29-73ce-41a6-809f-6363ba21b47e\'  -Name DCSettingIndex -Value 0
Write-Host "Turn off hybrid sleep (on battery) is enabled" -ForegroundColor Green

# Turn off hybrid sleep (plugged in) is enabled
Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\94ac6d29-73ce-41a6-809f-6363ba21b47e\'  -Name ACSettingIndex -Value 0
Write-Host "Turn off hybrid sleep (plugged in) is enabled" -ForegroundColor Green

# Show hibernate in the power options menu is disabled
Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer\'  -Name ShowHibernateOption -Value 0
Write-Host "Show hibernate in the power options menu is disabled" -ForegroundColor Green

# Show sleep in the power options menu is disabled
Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer\'  -Name ShowSleepOption -Value 0
Write-Host "Show sleep in the power options menu is disabled" -ForegroundColor Green

#------------------------------------------------------------#
# Powershell
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "Password and logon authentication policy" -ForegroundColor Yellow
		
# Allowing any PowerShell script to execute exposes a workstation to the risk that a malicious 
# script may be unwittingly executed by a user. To reduce this risk, users should not have the 
# ability to execute PowerShell scripts; however, if using PowerShell scripts is an essential 
# business requirement, only signed scripts should be allowed to execute. Ensuring that only 
# signed scripts are allowed to execute can provide a level of assurance that a script is 
# trusted and has been endorsed as having a legitimate business purpose.

# For more information on how to effectively implement PowerShell see the Securing PowerShell in the Enterprise publication.
# https://www.cyber.gov.au/node/1293

Set-ItemProperty -Path  'Registry::HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\' -Name EnableScriptBlockLogging -Value 1
Write-Host "Turn on PowerShell Script Block Logging is enabled in Local Machine GP" -ForegroundColor Green
Set-ItemProperty -Path  'Registry::HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\' -Name EnableScriptBlockLogging -Value 1
Write-Host "Turn on PowerShell Script Block Logging is enabled in User GP" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\' -Name EnableScriptBlockInvocationLogging -Value 1
Write-Host "Turn on PowerShell Script Block Invocation Logging is enabled in Local Machine GP" -ForegroundColor Green
Set-ItemProperty -Path  'Registry::HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\' -Name EnableScriptBlockInvocationLogging -Value 1
Write-Host "Turn on PowerShell Script Block Invocation Logging is enabled in User GP" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKLM\Software\Policies\Microsoft\Windows\PowerShell\' -Name EnableScripts -Value 1
Write-Host "Turn on Script Execution is enabled in Local Machine GP" -ForegroundColor Green
Set-ItemProperty -Path  'Registry::HKCU\Software\Policies\Microsoft\Windows\PowerShell\' -Name EnableScripts -Value 1
Write-Host "Turn on Script Execution is enabled in User GP" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKLM\Software\Policies\Microsoft\Windows\PowerShell\' -Name ExecutionPolicy -Value 0
Write-Host "Allow only signed powershell scripts is enabled in Local Machine GP" -ForegroundColor Green
Set-ItemProperty -Path  'Registry::HKCU\Software\Policies\Microsoft\Windows\PowerShell\' -Name ExecutionPolicy -Value 0
Write-Host "Allow only signed powershell scripts is enabled in User GP" -ForegroundColor Green

#------------------------------------------------------------#
# Registry Editing Tools
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "Registry Editing Tools" -ForegroundColor Yellow
		
# One method for malicious code to maintain persistence (i.e. remain after a workstation is rebooted)
# is to use administrative privileges to modify the registry (as standard privileges only allow 
# viewing of the registry). To reduce this risk, users should not have the ability to modify the 
# registry using registry editing tools (i.e. regedit) or to make silent changes to the registry (i.e. using .reg files).

Set-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System\'  -Name DisableRegistryTools -Value 2
Write-Host "Prevent access to registry editing tools is enabled" -ForegroundColor Green

#------------------------------------------------------------#
# Remote Assistance
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "Remote Assistance" -ForegroundColor Yellow

# While Remote Assistance can be a useful business tool to allow system administrators to remotely 
# administer workstations, it can also pose a risk. When a user has a problem with their workstation 
# they can generate a Remote Assistance invitation. This invitation authorises anyone that has 
# access to it to remotely control the workstation that issued the invitation. Invitations can be 
# sent by email, instant messaging or saved to a file. If an adversary manages to intercept an 
# invitation they will be able to use it to access the user’s workstation. Additionally, if 
# network traffic on port 3389 is not blocked from reaching the internet, users may send Remote 
# Assistance invitations over the internet which could allow for remote access to their 
# workstation by an adversary. While Remote Assistance only grants access to the privileges 
# of the user that generated the request, an adversary could install a key logging application 
# on the workstation in preparation of a system administer using their privileged credentials 
# to fix any problems. To reduce this risk, Remote Assistance should be disabled.


Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\policies\Microsoft\Windows NT\Terminal Services\'  -Name fAllowUnsolicited -Value 0
Write-Host "Configure Offer Remote Assistance is disabled" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\policies\Microsoft\Windows NT\Terminal Services\'  -Name fAllowToGetHelp -Value 0
Write-Host "Configure Solicited Remote Assistance is disabled" -ForegroundColor Green

#------------------------------------------------------------#
# Remote Desktop Services
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "Remote Desktop Services" -ForegroundColor Yellow

# While remote desktop access may be convenient for legitimate users to access workstations 
# across a network, it also allows an adversary to access other workstations once they have 
# compromised an initial workstation and user’s credentials. This risk can be compounded if 
# an adversary can compromise domain administrator credentials or common local administrator 
# credentials. To reduce this risk, Remote Desktop Services should be disabled.

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\'  -Name fDenyTSConnections -Value 0
Write-Host "Allow users to connect remotely by using Remote Desktop Services is disabled" -ForegroundColor Green

# Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment
# Write-Host "No members are allowed to logon through remote desktop services, this setting is compliant" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CredentialsDelegation\'  -Name AllowProtectedCreds -Value 1
Write-Host "Remote host allows delegation of non-exportable credentials is enabled" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\'  -Name AuthenticationLevel -Value 1
Write-Host "Configure server authentication for client is enabled" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\'  -Name DisablePasswordSaving -Value 1
Write-Host "Do not allow passwords to be saved is enabled" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\'  -Name fDisableForcibleLogoff -Value 1
Write-Host "Deny logoff of an administrator logged in to the console session is enabled" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\'  -Name fDisableClip -Value 1
Write-Host "Do not allow Clipboard redirection is enabled" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\'  -Name fDisableCdm -Value 1
Write-Host "Do not allow drive redirection is enabled" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\'  -Name fPromptForPassword -Value 1
Write-Host "Always prompt for password upon connection is enabled" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\'  -Name fWritableTSCCPermTab -Value 0
Write-Host "Do not allow local administrators to customize permissions is enabled" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\'  -Name fEncryptRPCTraffic -Value 1
Write-Host "Require secure RPC communication is enabled" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\'  -Name SecurityLayer -Value 2
Write-Host "Require use of specific security layer for remote (RDP) connections is set to SSL" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\'  -Name UserAuthentication -Value 1
Write-Host "Require user authentication for remote connections by using Network Level Authentication is enabled" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\'  -Name MinEncryptionLevel -Value 3
Write-Host "Set client connection encryption level is set to high" -ForegroundColor Green

#------------------------------------------------------------#
# Remote Procedure Call
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "Remote Procedure Call" -ForegroundColor Yellow

# Remote Procedure Call (RPC) is a technique used for facilitating client and server application 
# communications using a common interface. RPC is designed to make client and server interaction 
# easier and safer by using a common library to handle tasks such as security, synchronisation 
# and data flows. If unauthenticated communications are allowed between client and server 
# applications, it could result in accidental disclosure of sensitive information or the 
# failure to take advantage of RPC security functionality. To reduce this risk, all RPC 
# clients should authenticate to RPC servers.

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Rpc\'  -Name RestrictRemoteClients -Value 1
Write-Host "Restrict Unauthenticated RPC clients is enabled" -ForegroundColor Green


#------------------------------------------------------------#
# Reporting system information
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "Reporting system information" -ForegroundColor Yellow

# Microsoft Windows contains a number of in-built functions to, often automatically and transparently, 
# report system information to Microsoft. This includes system errors and crash information as well as 
# inventories of applications, files, devices and drivers on the system. If captured by an adversary, 
# this information could expose potentially sensitive information on workstations. This information 
# could also subsequently be used by an adversary to tailor malicious code to target specific 
# workstations or users. To reduce this risk, all in-built functions that report potentially 
# sensitive system information should be directed to a corporate Windows Error Reporting server.

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy\'  -Name DisableQueryRemoteServer -Value 0
Write-Host "Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider is disabled" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppCompat\'  -Name DisableInventory -Value 1
Write-Host "Turn off Inventory Collector is enabled" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppCompat\'  -Name DisableUAR -Value 1
Write-Host "Turn off Steps Recorder is enabled" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKLM\Software\Policies\Microsoft\Windows\DataCollection\' -Name AllowTelemetry -Value 0
Write-Host "Allow Telemetry is enabled in Local Machine GP" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKCU\Software\Policies\Microsoft\Windows\DataCollection\' -Name AllowTelemetry -Value 0
Write-Host "Allow Telemetry is enabled in User GP" -ForegroundColor Green

# Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\'  -Name CorporateWerServer -Value 0
# Write-Host "The corporate WER server is configured" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\'  -Name CorporateWerUseSSL -Value 1
Write-Host "Connect using SSL is enabled" -ForegroundColor Green


#------------------------------------------------------------#
# Safe Mode
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "Safe Mode" -ForegroundColor Yellow

# An adversary with standard user credentials that can boot into Microsoft Windows using 
# Safe Mode, Safe Mode with Networking or Safe Mode with Command Prompt options may be able 
# to bypass system protections and security functionality. To reduce this risk, users with 
# standard credentials should be prevented from using Safe Mode options to log in.

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\'  -Name SafeModeBlockNonAdmins -Value 1
Write-Host "Block Non-Administrators in Safe Mode is enabled" -ForegroundColor Green

#------------------------------------------------------------#
# Secure channel communications
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "Secure channel communications" -ForegroundColor Yellow

# Periodically, workstations connected to a domain will communicate with the domain controllers. 
# If an adversary has access to unprotected network communications they may be able to capture 
# or modify sensitive information communicated between workstations and the domain controllers. 
# To reduce this risk, all secure channel communications should be signed and encrypted with strong session keys.

Set-ItemProperty -Path "Registry::HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\" -Name RequireSignOrSeal -Value 1
Write-Host "Domain member: Digitally encrypt or sign secure channel data (always) is enabled" -ForegroundColor Green
   
Set-ItemProperty -Path "Registry::HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\" -Name SealSecureChannel -Value 1
Write-Host "Domain member: Digitally encrypt secure channel data (when possible) is enabled" -ForegroundColor Green
   
Set-ItemProperty -Path "Registry::HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\" -Name SignSecureChannel -Value 1
Write-Host "Domain member: Digitally sign secure channel data (when possible) is enabled" -ForegroundColor Green

Set-ItemProperty -Path "Registry::HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\" -Name RequireStrongKey -Value 1
Write-Host "Domain member: Require strong (Windows 2000 or later) session key is enabled" -ForegroundColor Green

#------------------------------------------------------------#
# Security policies
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "Security policies" -ForegroundColor Yellow

# By failing to comprehensively specify security policies, an adversary may be able to exploit 
# weaknesses in a workstation’s Group Policy settings to gain access to sensitive information. 
# To reduce this risk, security policies should be comprehensively specified.

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\wcmsvc\wifinetworkmanager\config\'  -Name AutoConnectAllowedOEM -Value 0
Write-Host "Allow Windows to automatically connect to suggested open hotspots, to networks shared by contacts, and to hotspots offering paid services is disabled" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CloudContent\'  -Name DisableWindowsConsumerFeatures -Value 1
Write-Host "Turn off Microsoft consumer experiences is enabled" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer\'  -Name NoHeapTerminationOnCorruption -Value 0
Write-Host "Turn off heap termination on corruption is disabled" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\'  -Name PreXPSP2ShellProtocolBehavior -Value 0
Write-Host "Turn off shell protocol protected mode is disabled" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Feeds\' -Name DisableEnclosureDownload -Value 1
Write-Host "Prevent downloading of enclosures is enabled in Local Machine GP" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKCU\Software\Policies\Microsoft\Internet Explorer\Feeds\' -Name DisableEnclosureDownload -Value 1
Write-Host "Prevent downloading of enclosures is enabled in User GP" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search\'  -Name AllowIndexingEncryptedStoresOrItems -Value 0
Write-Host "Allow indexing of encrypted files is disabled" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\GameDVR\'  -Name AllowGameDVR -Value 0
Write-Host "Enables or disables Windows Game Recording and Broadcasting is disabled" -ForegroundColor Green

Set-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\ -Name DisablePasswordChange -Value 0
Write-Host "Domain member: Disable machine account password changes is disabled" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\'  -Name MaximumPasswordAge -Value 30
Write-Host "Domain member: Maximum machine account password age is set to a compliant setting" -ForegroundColor Green

Set-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\pku2u\ -Name AllowOnlineID -Value 0
Write-Host "Network security: Allow PKU2U authentication requests to this computer to use online identities is disabled" -ForegroundColor Green

Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LDAP\' -Name LDAPClientIntegrity -Value 1
Write-Host "Network security: LDAP client signing requirements is enabled and set to Negotiate Signing" -ForegroundColor Green

Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel\' -Name ObCaseInsensitive -Value 1
Write-Host "System objects: Require case insensitivity for non-Windows subsystems is enabled" -ForegroundColor Green

Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\' -Name ProtectionMode -Value 1
Write-Host "System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links) is enabled" -ForegroundColor Green

#------------------------------------------------------------#
# Server Message Block sessions
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "Server Message Block sessions" -ForegroundColor Yellow

# An adversary that has access to network communications may attempt to use session hijacking tools to interrupt, 
# terminate or steal a Server Message Block (SMB) session. This could potentially allow an adversary to modify 
# packets and forward them to a SMB server to perform undesirable actions or to pose as the server or client 
# after a legitimate authentication has taken place to gain access to sensitive information. To reduce this 
# risk, all communications between SMB clients and servers should be signed, with any passwords used appropriately encrypted.

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MrxSmb10\'  -Name Start -Value 4
Write-Host "Configure SMB v1 client driver is disabled" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\'  -Name SMB1 -Value 0
Write-Host "Configure SMB v1 server is disabled" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\'  -Name RequireSecuritySignature -Value 1
Write-Host "Microsoft Network Client: Digitally sign communications (always) is enabled" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\'  -Name EnableSecuritySignature -Value 1
Write-Host "Microsoft network client: Digitally sign communications (if server agrees) is enabled" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\'  -Name EnablePlainTextPassword -Value 0
Write-Host "Microsoft network client: Send unencrypted password to third-party SMB servers is disabled" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\'  -Name AutoDisconnect -Value 15
Write-Host "Microsoft network server: Amount of idle time required before suspending session is less than or equal to 15 mins" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\'  -Name RequireSecuritySignature -Value 1
Write-Host "Microsoft network server: Digitally sign communications (always) is enabled" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\'  -Name EnableSecuritySignature -Value 1
Write-Host "Microsoft network server: Digitally sign communications (if client agrees) is enabled" -ForegroundColor Green

#------------------------------------------------------------#
# Session locking
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "Session locking" -ForegroundColor Yellow

# An adversary with physical access to an unattended workstation with an unlocked session may attempt 
# to inappropriately access sensitive information or conduct actions that won’t be attributed to them. 
# To reduce this risk, a session lock should be configured to activate after a maximum of 15 minutes 
# of user inactivity. Furthermore, be aware that information or alerts may be displayed on the lock 
# screen. To reduce the risk of unauthorised information disclosure, minimise the amount of information 
# that the lock screen is permitted to display.

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Personalization\'  -Name NoLockScreenCamera -Value 1
Write-Host "Prevent enabling lock screen camera is enabled" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Personalization\'  -Name NoLockScreenSlideshow -Value 1
Write-Host "Prevent enabling lock screen slide show is enabled" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System\'  -Name AllowDomainDelayLock -Value 0
Write-Host "Allow users to select when a password is required when resuming from connected standby is disabled" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System\'  -Name DisableLockScreenAppNotifications -Value 1
Write-Host "Turn off app notifications on the lock screen is enabled" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer\'  -Name ShowLockOption -Value 1
Write-Host "Show lock in the user tile menu is enabled" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsInkWorkspace\'  -Name AllowWindowsInkWorkspace -Value 1
Write-Host "Allow Windows Ink Workspace is on but dissalow access above lock" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\'  -Name inactivitytimeoutsecs -Value '900'
Write-Host "The machine inactivity limit has been set to $bKErRNAU3b4k6hI seconds which is a compliant setting" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop\'  -Name ScreenSaveActive -Value 1
Write-Host "Enable screen saver is enabled" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop\'  -Name ScreenSaverIsSecure -Value 1
Write-Host "Password protect the screen saver is enabled" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop\'  -Name ScreenSaveTimeOut -Value '900'
Write-Host "Screen saver timeout is set compliant" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\'  -Name NoToastApplicationNotificationOnLockScreen -Value 1
Write-Host "Turn off toast notifications on the lock screen is enabled" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\CloudContent\'  -Name DisableThirdPartySuggestions -Value 1
Write-Host "Do not suggest third-party content in Windows spotlight is enabled" -ForegroundColor Green

#------------------------------------------------------------#
# Software-based firewalls
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "Software-based firewalls" -ForegroundColor Yellow
		
# Network firewalls often fail to prevent the propagation of malicious code on a network, or an 
# adversary from extracting sensitive information, as they generally only control which ports or 
# protocols can be used between segments on a network. Many forms of malicious code are designed 
# specifically to take advantage of this by using common protocols such as HTTP, HTTPS, SMTP and DNS. 
# To reduce this risk, software-based firewalls that filter both incoming and outgoing traffic 
# should be appropriately implemented. Software-based firewalls are more effective than network 
# firewalls as they can control which applications and services can communicate to and from workstations. 
# The in-built Windows firewall can be used to control both inbound and outbound traffic for specific applications.		

#------------------------------------------------------------#
# Sound Recorder
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "Sound Recorder" -ForegroundColor Yellow
		
# Sound Recorder is a feature of Microsoft Windows that allows audio from a device with a microphone 
# to be recorded and saved as an audio file on the local hard drive. An adversary with remote access 
# to a workstation can use this functionality to record sensitive conversations in the vicinity of the workstation. 
# To reduce this risk, Sound Recorder should be disabled.

Set-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\SoundRecorder\'  -Name Soundrec -Value 1
Write-Host "Do not allow Sound Recorder to run is enabled" -ForegroundColor Green

#------------------------------------------------------------#
# Standard Operating Environment
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "Standard Operating Environment" -ForegroundColor Yellow
		
# When users are left to setup, configure and maintain their own workstations it can very easily lead 
# to an inconsistent and insecure environment where particular workstations are more vulnerable than others. 
# This inconsistent and insecure environment can easily allow an adversary to gain an initial foothold 
# on a network. To reduce this risk, workstations should connect to a domain using a Standard Operating 
# Environment that is centrally controlled and configured by experienced information technology and 
# information security professionals. However, in some cases, cloud-based domain services may be more 
# effective in deploying workstation configurations to a mobile and disparate workforce. In particular, 
# security objectives may be achieved without the need to create ‘gold’ images and can offer more 
# flexible enrolment processes. However, enrolment methods, such as Microsoft Intune self-enrolment, 
# may introduce their own security risks, such as leaving behind local administrator accounts.

#------------------------------------------------------------#
# System backup and restore
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "System backup and restore" -ForegroundColor Yellow

# An adversary that compromises a user account with privileges to backup files and directories can 
# use this privilege to backup the contents of a workstation. This content can then be transferred to 
# a non-domain connected workstation where the adversary has administrative access. From here an 
# adversary can restore the contents and take ownership, thereby circumventing all original access 
# controls that were in place. In addition, if a user has privileges to restore files and directories, 
# an adversary could exploit this privilege by using it to either restore previous versions of files 
# that may have been removed by system administrators as part of malicious code removal activities or 
# to replace existing files with malicious variants. To reduce this risk, the ability to use backup 
# and restore functionality should be limited to administrators.

# Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Backup Files and Directories. Only Administrators should be members of this setting" -ForegroundColor White
# Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Restore Files and Directories. Only Administrators should be members of this setting" -ForegroundColor White

#------------------------------------------------------------#
# System cryptography
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "System cryptography" -ForegroundColor Yellow
		
# By default, when cryptographic keys are stored in Microsoft Windows, users can access them without 
# first entering a password to unlock the certificate store. An adversary that compromises a workstation, 
# or gains physical access to an unlocked workstation, can use these user keys to access sensitive 
# information or resources that are cryptographically protected. To reduce this risk, strong encryption 
# algorithms and strong key protection should be used on workstations.

Set-ItemProperty -Path "Registry::HKLM\SOFTWARE\Policies\Microsoft\Cryptography" -Name ForceKeyProtection -Value 2 
Write-Host "System cryptography: Force strong key protection for user keys stored on the computer is set to user must enter a password each time they use a key" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Centrify\CentrifyDC\Settings\Fips\'  -Name fips.mode.enable -Value 'true'
Write-Host "Use FIPS compliant algorithms for encryption, hashing and signing is enabled" -ForegroundColor Green

#------------------------------------------------------------#
# System cryptography
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "System cryptography" -ForegroundColor Yellow

# By default, when cryptographic keys are stored in Microsoft Windows, users can access them without first 
# entering a password to unlock the certificate store. An adversary that compromises a workstation, 
# or gains physical access to an unlocked workstation, can use these user keys to access sensitive 
# information or resources that are cryptographically protected. To reduce this risk, strong 
# encryption algorithms and strong key protection should be used on workstations.

# Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options

#------------------------------------------------------------#
# User rights policies
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "User rights policies" -ForegroundColor Yellow

# 'Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment'" -ForegroundColor White

# By failing to comprehensively specify user rights policies, an adversary may be able to exploit weaknesses in a workstation’s Group Policy settings to gain access to sensitive information. To reduce this risk, user rights policies should be comprehensively specified.

#------------------------------------------------------------#
# Virtualised web and email access
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "Virtualised web and email access" -ForegroundColor Yellow

# An adversary can often deliver malicious code directly to workstations via external 
# web and email access. Once a workstation has been exploited, an adversary can 
# use these same communication paths for bi-directional communications to control 
# their malicious code. To reduce this risk, web and email access on workstations 
# should occur through a non-persistent virtual environment (i.e. using virtual 
# desktops or virtual applications). When using a virtual environment, workstations 
# will receive additional protection against intrusion attempts targeted at exploiting 
# security vulnerabilities in web browsers and email clients as any attempts, if successful, 
# will execute in a non-persistent virtual environment rather than on a local workstation.

#------------------------------------------------------------#
# Web Proxy Auto Discovery protocol
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "Web Proxy Auto Discovery protocol" -ForegroundColor Yellow
		
# The Web Proxy Auto Discovery (WPAD) protocol assists with the automatic detection of proxy settings for web browsers. 
# Unfortunately, WPAD has suffered from a number of severe security vulnerabilities. Organisations that do 
# not rely on the use of the WPAD protocol should disable it. This can be achieved by modifying each 
# workstation’s host file at %SystemDrive%\Windows\System32\Drivers\etc\hosts to create the 
# following entry: 255.255.255.255 wpad.		
		
#------------------------------------------------------------#
# Windows Remote Management
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "Windows Remote Management" -ForegroundColor Yellow
			
Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Client\'  -Name AllowBasic -Value 0
Write-Host "Allow Basic authentication is disabled" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Client\'  -Name AllowUnencryptedTraffic -Value 0
Write-Host "Allow unencrypted traffic is disabled" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Client\'  -Name AllowDigest -Value 0
Write-Host "Disallow Digest authentication is enabled" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service\'  -Name AllowBasic -Value 0
Write-Host "Allow Basic authentication is disabled" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service\'  -Name AllowUnencryptedTraffic -Value 0
Write-Host "Allow unencrypted traffic is disabled" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service\'  -Name DisableRunAs -Value 1
Write-Host "Disallow WinRM from storing RunAs credentials is enabled" -ForegroundColor Green

#------------------------------------------------------------#
# Windows Remote Shell access
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "Windows Remote Shell access" -ForegroundColor Yellow

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service\WinRS\'  -Name AllowRemoteShellAccess -Value 0
Write-Host "Allow Remote Shell Access is disabled" -ForegroundColor Green

#------------------------------------------------------------#
# Windows Search and Cortana
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "Windows Search and Cortana" -ForegroundColor Yellow

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search\'  -Name AllowCortana -Value 0
Write-Host "Allow Cortana is disabled" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search\'  -Name ConnectedSearchUseWeb -Value 0
Write-Host "Don't search the web or display web results in Search is enabled" -ForegroundColor Green

# Low priorities
# The following recommendations, listed in alphabetical order, should be treated as low priorities when hardening Microsoft Windows 10 workstations.

#------------------------------------------------------------#
# Displaying file extensions
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "Displaying file extensions" -ForegroundColor Yellow

# When extensions for known file types are hidden, an adversary can more easily use social engineering techniques to convince users to execute malicious email attachments. For example, a file named vulnerability_assessment.pdf.exe could appear as vulnerability_assessment.pdf to a user. To reduce this risk, hiding extensions for known file types should be disabled. Showing extensions for all known file types, in combination with user education and awareness of dangerous email attachment file types, can help reduce the risk of users executing malicious email attachments.

Set-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'  -Name HideFileExt -Value 0
Write-Host "Display file extensions is enabled" -ForegroundColor Green

#------------------------------------------------------------#
# File and folder security properties
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "File and folder security properties" -ForegroundColor Yellow

Set-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\'  -Name NoSecurityTab -Value 1
Write-Host "Remove Security tab is enabled" -ForegroundColor Green

#------------------------------------------------------------#
# Location awareness
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "Location awareness" -ForegroundColor Yellow

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LocationAndSensors\'  -Name DisableLocation -Value 1
Write-Host "Turn off location is enabled" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LocationAndSensors\'  -Name DisableLocationScripting -Value 1
Write-Host "Turn off location scripting is enabled" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LocationAndSensors\'  -Name DisableWindowsLocationProvider -Value 1
Write-Host "Turn off Windows Location Provider is enabled" -ForegroundColor Green

#------------------------------------------------------------#
# Microsoft Store
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "Microsoft Store" -ForegroundColor Yellow

Set-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Explorer\'  -Name NoUseStoreOpenWith -Value 1
Write-Host "Turn off access to the Store is enabled" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\WindowsStore\'  -Name RemoveWindowsStore -Value 1
Write-Host "Turn off the Store application is enabled" -ForegroundColor Green

#------------------------------------------------------------#
# Resultant Set of Policy reporting
#------------------------------------------------------------#
        Write-Host "`n"
        Write-Host "Resultant Set of Policy reporting" -ForegroundColor Yellow

Set-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\System\'  -Name DenyRsopToInteractiveUser -Value 1
Write-Host "Determine if interactive users can generate Resultant Set of Policy data is enabled" -ForegroundColor Green

# Further information
# The Information Security Manual is a cyber security framework that organisations 
# can apply to protect their systems and data from cyber threats. The advice in the 
# Strategies to Mitigate Cyber Security Incidents, along with its Essential Eight, 
# complements this framework.
