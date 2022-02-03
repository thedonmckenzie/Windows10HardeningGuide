# Windows 10 Hardening Guide - Setting Applicable Registry Keys via PowerShell based on https://www.cyber.gov.au/acsc/view-all-content/publications/hardening-microsoft-windows-10-version-21h1-workstations
# This script looks to set as many of of the recommendations as possible, without using Group Policy (to allow for non Windows Pro licenced users).

	# Workstations are often targeted by an adversary using malicious websites, emails or removable media in an attempt to extract sensitive information. Hardening workstations 
	# is an important part of reducing this risk.
	# The ACSC provides recommendations on hardening workstations using Enterprise and Education editions of Microsoft Windows 10 version 21H1. Before implementing 
	# recommendations in this publication, thorough testing should be undertaken to ensure the potential for unintended negative impacts on business processes is reduced as much as possible.
	# While this publication refers to workstations, most recommendations are equally applicable to servers (with the exception of Domain Controllers) using Microsoft Windows 
	# Server version 21H1 or Microsoft Windows Server 2019.
	# Security features discussed in this publication, along with the names and locations of Group Policy settings, are taken from Microsoft Windows 10 version 21H1 â€“ some 
	# differences will exist for earlier versions of Microsoft Windows 10.
	# For cloud-based device managers, such as Microsoft Endpoint Manager, equivalents can be found for many of the Group Policy settings. Alternatively, there is often a 
	# function to import Group Policy settings into cloud-based device managers.

#------------------------------------------------------------#
# Application Hardening
#------------------------------------------------------------#
		Write-Host "`n"
        Write-Host "Application Hardening" -ForegroundColor Yellow
		Write-Host "Please review comments of this script for more information" -ForegroundColor Green
	# When applications are installed they are often not pre-configured in a secure state. By default, many applications enable functionality that isnâ€™t required by any users 
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
    # (including the userâ€™s passphrase in plaintext if WDigest authentication is enabled) to allow for access to network resources 
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
	# Microsoft to help prevent security vulnerabilities from being exploited are not implemented. Microsoft Defenderâ€™s exploit protection functionality, a 
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
		Disable-LocalUser -Name â€œAdministratorâ€
			Write-Host "In Built Administrator Account Disabled" -ForegroundColor Green

	# If a common local administrator account absolutely must be used for workstation management then Microsoftâ€™s Local Administrator Password Solution (LAPS) 
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
	# Furthermore, as Microsoft Edge contains an â€˜IE modeâ€™, Internet Explorer 11 should be disabled or removed from Microsoft Windows 10 to reduce the operating 
	# systemâ€™s attack surface.

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
	# brute forces captured password hashes can gain access to workstations if multi-factor authentication hasnâ€™t been implemented. To reduce 
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
	# To reduce this risk, users that donâ€™t require privileged access should not be granted privileged accounts while users that require privileged access 
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
	
	# Allowing unlimited attempts to access workstations will fail to prevent an adversaryâ€™s attempts to brute force authentication measures. 
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
			Write-Host "Include command line in process creation events is enabled" -ForegroundColor Green}

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

# An adversary with access to a workstationâ€™s Basic Input/Output System (BIOS) or UEFI can modify the hardware 
# configuration of the workstation to introduce attack vectors or weaken security functionality within the workstationâ€™s 
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
# to connect to an organisationâ€™s wired network and a wireless interface to connect to another non-organisation 
# controlled network such as a public wireless hotspot. When bridges are created between such networks an adversary 
# can directly access the wired network from the wireless network to extract sensitive information. 
# To reduce this risk, the ability to install and configure network bridges between different networks should be disabled. 
# This wonâ€™t prevent an adversary from compromising a workstation via the wireless network and then using malicious 
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

Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses\" -Name 1 -Value '{d48179be-ec20-11d1-b6b8-00c04fa372a7}'
Write-Host "{d48179be-ec20-11d1-b6b8-00c04fa372a7} is included on the banned device list to prevent DMA installations" -ForegroundColor Green

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

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56308-b6bf-11d0-94f2-00a0c91efb8b}\'  -Name Deny_Execute -Value 1
Write-Host "CD and DVD: Deny execute access is enabled in local machine group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56308-b6bf-11d0-94f2-00a0c91efb8b}\'  -Name Deny_Read -Value 0
Write-Host "CD and DVD: Deny read access is disabled in local machine group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56308-b6bf-11d0-94f2-00a0c91efb8b}\'  -Name Deny_Write -Value 1
Write-Host "CD and DVD: Deny write access is enabled in local machine group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKCU\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56308-b6bf-11d0-94f2-00a0c91efb8b}\'  -Name Deny_Read -Value 0
Write-Host "CD and DVD: Deny read access is disabled in user group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKCU\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56308-b6bf-11d0-94f2-00a0c91efb8b}\'  -Name Deny_Write -Value 1
Write-Host "CD and DVD: Deny write access is enabled in user group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKLM\Software\Policies\Microsoft\Windows\RemovableStorageDevices\Custom\Deny_Read\' -Name Deny_Read -Value 0
Write-Host "Custom Classes: Deny read access is disabled in local machine group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKLM\Software\Policies\Microsoft\Windows\RemovableStorageDevices\Custom\Deny_Write\' -Name Deny_Write -Value 1
Write-Host "Custom Classes: Deny write access is enabled in local machine group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\RemovableStorageDevices\Custom\Deny_Read\' -Name Deny_Read -Value 0
Write-Host "Custom Classes: Deny read access is disabled in user group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\RemovableStorageDevices\Custom\Deny_Write\'  -Name Deny_Write -Value 1
Write-Host "Custom Classes: Deny write access is enabled in user group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56311-b6bf-11d0-94f2-00a0c91efb8b}\'  -Name Deny_Execute -Value 1
Write-Host "Floppy Drives: Deny execute access is enabled in local machine group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKLM\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56311-b6bf-11d0-94f2-00a0c91efb8b}\'  -Name Deny_Read -Value 0
Write-Host "Floppy Drives: Deny read access is disabled in local machine group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKLM\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56311-b6bf-11d0-94f2-00a0c91efb8b}\'  -Name Deny_Write -Value 1
Write-Host "Floppy Drives: Deny write access is enabled in local machine group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56311-b6bf-11d0-94f2-00a0c91efb8b}\'  -Name Deny_Read -Value 0
Write-Host "Floppy Drives: Deny read access is disabled in user group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56311-b6bf-11d0-94f2-00a0c91efb8b}\'  -Name Deny_Write -Value 1
Write-Host "Floppy Drives: Deny write access is enabled in user group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}\'  -Name Deny_Execute -Value 1
Write-Host "Removable Disks: Deny execute access is enabled in local machine group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKLM\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}\'  -Name Deny_Read -Value 0
Write-Host "Removable Disks: Deny read access is disabled in local machine group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKLM\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}\'  -Name Deny_Write -Value 1
Write-Host "Removable Disks: Deny write access is enabled in local machine group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}\'  -Name Deny_Read -Value 0
Write-Host "Removable Disks: Deny read access is disabled in user group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}\'  -Name Deny_Write -Value 1
Write-Host "Removable Disks: Deny write access is enabled in user group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630b-b6bf-11d0-94f2-00a0c91efb8b}\'  -Name Deny_Execute -Value 1
Write-Host "Tape Drives: Deny execute access is enabled in local machine group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630b-b6bf-11d0-94f2-00a0c91efb8b}\'  -Name Deny_Read -Value 0
Write-Host "Tape Drives: Deny read access is disabled in user group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630b-b6bf-11d0-94f2-00a0c91efb8b}\'  -Name Deny_Write -Value 1
Write-Host "Tape Drives: Deny write access is enabled in user group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKLM\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630b-b6bf-11d0-94f2-00a0c91efb8b}\'  -Name Deny_Read -Value 0
Write-Host "Tape Drives: Deny read access is disabled in local machine group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKLM\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630b-b6bf-11d0-94f2-00a0c91efb8b}\'  -Name Deny_Write -Value 1
Write-Host "Tape Drives: Deny write access is enabled in local machine group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKLM\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{6AC27878-A6FA-4155-BA85-F98F491D4F33}\'  -Name Deny_Read -Value 0
Set-ItemProperty -Path  'Registry::HKLM\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{F33FDC04-D1AC-4E8E-9A30-19BBD4B108AE}\'  -Name Deny_Read -Value 0
Write-Host "WPD Devices: Deny read access is disabled in local machine group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKLM\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{6AC27878-A6FA-4155-BA85-F98F491D4F33}\'  -Name Deny_Write -Value 1
Set-ItemProperty -Path  'Registry::HKLM\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{F33FDC04-D1AC-4E8E-9A30-19BBD4B108AE}\'  -Name Deny_Write -Value 1
Write-Host "WPD Devices: Deny write access is enabled in local machine group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKCU\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{6AC27878-A6FA-4155-BA85-F98F491D4F33}\'  -Name Deny_Read -Value 0
Set-ItemProperty -Path  'Registry::HKCU\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{F33FDC04-D1AC-4E8E-9A30-19BBD4B108AE}\'  -Name Deny_Read -Value 0
Write-Host "WPD Devices: Deny read access is disabled in user group policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKCU\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{6AC27878-A6FA-4155-BA85-F98F491D4F33}\'  -Name Deny_Write -Value 1
Set-ItemProperty -Path  'Registry::HKCU\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{F33FDC04-D1AC-4E8E-9A30-19BBD4B108AE}\'  -Name Deny_Write -Value 1
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
# affect a userâ€™s ability to access shared drives and printers on a network.

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
# domain level. To ensure these policies arenâ€™t weakened, support for Local Group 
# Policy settings should also be disabled.

# Configure registry policy processing
Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\'  -Name NoGPOListChanges -Value 0
Write-Host "Configure registry policy processing is enabled" -ForegroundColor Green
Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}\'  -Name NoGPOListChanges -Value 0
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

Set-ItemProperty -Path  'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer\'  -Name AlwaysInstallElevated -Value 0
Write-Host "Always install with elevated privileges is disabled in local machine policy" -ForegroundColor Green

Set-ItemProperty -Path  'Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer\'  -Name AlwaysInstallElevated -Value 0
Write-Host "Always install with elevated privileges is disabled in user policy" -ForegroundColor Green
