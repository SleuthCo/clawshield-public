---
framework: "MITRE ATT&CK"
version: "15.1"
domain: "Persistence"
agent: "sentinel"
tags: ["mitre", "attck", "persistence", "backdoor", "scheduled-task", "account-manipulation"]
last_updated: "2025-06-01"
chunk_strategy: "technique"
---

# MITRE ATT&CK — Persistence (TA0003)

Persistence consists of techniques adversaries use to maintain their foothold across system restarts, credential changes, and other interruptions. Persistence mechanisms allow adversaries to maintain access to systems without needing to repeat initial access techniques.

## T1098: Account Manipulation

**Technique Description:** Adversaries manipulate existing accounts to maintain and elevate access. This includes modifying credentials, permissions, and group memberships.

**T1098.001: Additional Cloud Credentials**
- Adding credentials to cloud service principals or user accounts
- Creating new access keys for AWS IAM users
- Adding certificates or secrets to Azure AD app registrations
- Adding SSH keys to cloud compute instance metadata
- Registering new OAuth applications with broad permissions

**T1098.002: Additional Email Delegate Permissions**
- Adding mail forwarding rules to exfiltrate data
- Granting Full Access or Send As permissions to attacker-controlled accounts
- Creating inbox rules to hide security notifications
- Modifying calendar delegate access for reconnaissance

**T1098.003: Additional Cloud Roles**
- Adding Global Administrator role in Azure AD
- Assigning IAM policy with administrative permissions in AWS
- Granting Owner or Editor roles in GCP projects
- Elevating service account permissions

**T1098.004: SSH Authorized Keys**
- Adding attacker-controlled SSH public keys to authorized_keys
- Modifying SSH daemon configuration for alternative authentication
- Installing SSH certificates for persistent access

**T1098.005: Device Registration**
- Registering rogue devices in Azure AD / Entra ID
- Adding devices to MDM with attacker-controlled credentials
- Exploiting device registration flows for persistent access

**Detection Strategies:**
- Monitor Azure AD / Entra ID audit logs for credential and role changes
- Alert on new service principal credentials or certificate additions
- Track AWS CloudTrail for CreateAccessKey, AttachUserPolicy events
- Monitor email forwarding rule creation
- Alert on SSH authorized_keys modifications via file integrity monitoring
- Track group membership changes in directory services
- Detect newly registered devices in identity platforms

**Mitigations:**
- M1032: Multi-factor Authentication — enforce for all account modifications
- M1026: Privileged Account Management — restrict who can modify accounts
- M1018: User Account Management — monitor and restrict role assignments
- Implement Privileged Identity Management (PIM) with approval workflows
- Regular access reviews and certification campaigns
- Alert on any changes to high-privilege accounts

## T1136: Create Account

**Technique Description:** Adversaries create new accounts to maintain access. These accounts can be local, domain, or cloud accounts.

**T1136.001: Local Account**
- Create local administrator accounts on compromised systems
- Often named to blend with legitimate accounts (svc_backup, admin2)
- May be hidden from login screens by modifying registry or user properties

**T1136.002: Domain Account**
- Create accounts in Active Directory for persistent domain access
- Add accounts to privileged groups (Domain Admins, Enterprise Admins)
- Create accounts in organizational units less likely to be audited

**T1136.003: Cloud Account**
- Create IAM users in AWS with programmatic access
- Create Azure AD accounts with global admin privileges
- Create GCP service accounts with project-level permissions
- Create API keys and service credentials

**Detection Strategies:**
- Monitor Security Event ID 4720 (Windows) for local/domain account creation
- Alert on any account creation by non-authorized processes or users
- Monitor CloudTrail CreateUser, CreateLoginProfile events
- Track Azure AD audit logs for new user provisioning outside normal workflows
- Compare account lists against authorized personnel records
- Detect accounts created outside identity governance systems

**Mitigations:**
- M1032: Multi-factor Authentication for account management
- M1030: Network Segmentation — restrict account creation to authorized systems
- M1026: Privileged Account Management — limit who can create accounts
- Implement identity governance requiring approval workflows for account creation
- Automated reconciliation between directory services and HR systems

## T1053: Scheduled Task/Job

**Technique Description:** Adversaries abuse task scheduling functionality to facilitate initial or recurring execution of malicious code at defined intervals.

**T1053.002: At**
- Linux/Unix at command for one-time scheduled execution
- Windows at command (legacy) for scheduled task creation
- Used for delayed execution to evade immediate detection

**T1053.003: Cron**
- Linux/Unix cron jobs for recurring execution
- Crontab entries at user and system level
- Common persistence locations: /etc/crontab, /etc/cron.d/, /var/spool/cron/
- Systemd timers as modern alternative to cron

**T1053.005: Scheduled Task (Windows)**
- Windows Task Scheduler for recurring or triggered execution
- Created via schtasks.exe, COM objects, or PowerShell
- Can run as SYSTEM or specified user context
- Supports multiple trigger types: time-based, logon, event, idle
- XML task definitions can be imported for stealth
- Remote task creation via RPC for lateral movement

**T1053.007: Container Orchestration Job**
- Kubernetes CronJobs for recurring container execution
- Docker compose scheduled services
- Cloud container scheduled tasks (ECS scheduled tasks, Cloud Run jobs)

**Detection Strategies:**
- Monitor schtasks.exe and at.exe execution with command-line arguments
- Windows Event ID 4698: Scheduled task creation
- Windows Event ID 4699: Scheduled task deletion (cleanup attempt)
- Monitor crontab changes on Linux systems
- File integrity monitoring on cron directories
- Track Task Scheduler PowerShell cmdlet usage (Register-ScheduledTask)
- Monitor for tasks executing unusual binaries or scripts
- Kubernetes audit logs for CronJob creation

**Mitigations:**
- M1026: Privileged Account Management — restrict task creation to authorized users
- M1028: Operating System Configuration — disable at command, restrict cron access
- M1047: Audit — regularly review scheduled tasks across all systems
- Implement application allowlisting to control what scheduled tasks can execute
- Group Policy to restrict remote task creation

## T1543: Create or Modify System Process

**Technique Description:** Adversaries create or modify system-level processes to repeatedly execute malicious payloads as part of persistence.

**T1543.001: Launch Agent (macOS)**
- Create property list files in ~/Library/LaunchAgents/ for user-level persistence
- Execute on user login
- Disguised as legitimate Apple or third-party services

**T1543.002: Systemd Service (Linux)**
- Create or modify systemd unit files for persistent service execution
- Locations: /etc/systemd/system/, /usr/lib/systemd/system/, ~/.config/systemd/user/
- Services configured to restart on failure for resilience
- Can be set to execute before or after specific system targets

**T1543.003: Windows Service**
- Install malicious Windows services using sc.exe, PowerShell, or WMI
- Services run as SYSTEM by default providing high privileges
- Service DLL hijacking through modified ImagePath or ServiceDll
- Modify existing service configurations to point to malicious binaries
- Named to mimic legitimate Windows services

**T1543.004: Launch Daemon (macOS)**
- Create property list files in /Library/LaunchDaemons/ for system-level persistence
- Execute as root on system boot
- Requires elevated privileges to install

**Detection Strategies:**
- Monitor service creation: Windows Event ID 7045 (new service installed)
- Monitor sc.exe and New-Service PowerShell cmdlet usage
- File integrity monitoring on systemd unit file directories
- Monitor for unusual process parents (services.exe spawning unexpected children)
- Track modifications to existing service configurations
- Alert on services with executable paths in unusual locations (temp, user dirs)
- Monitor launchd plist creation on macOS

**Mitigations:**
- M1047: Audit — regularly review installed services across all systems
- M1028: Operating System Configuration — restrict service creation permissions
- M1022: Restrict File and Directory Permissions on service configuration directories
- Code signing enforcement for service binaries
- Application allowlisting preventing unauthorized service executables

## T1546: Event Triggered Execution

**Technique Description:** Adversaries establish persistence by configuring malicious content to execute in response to specific system events or user actions.

**T1546.001: Change Default File Association**
- Modify file type associations to execute malicious programs when files are opened
- Registry: HKEY_CLASSES_ROOT\\<extension>\\shell\\open\\command
- Can intercept execution of common file types

**T1546.002: Screensaver**
- Modify screensaver settings to execute malicious programs
- Registry: HKCU\\Control Panel\\Desktop\\SCRNSAVE.EXE
- Executes with current user privileges after idle timeout

**T1546.003: WMI Event Subscription**
- Create WMI event consumers that execute commands on defined triggers
- Extremely persistent: survives reboots, difficult to detect
- Three components: filter (trigger), consumer (action), binding (link)
- Common triggers: process creation, user logon, timer events
- Executes as SYSTEM with wmiprvse.exe as parent

**T1546.004: Unix Shell Configuration Modification**
- Modify shell profile files: .bashrc, .bash_profile, .zshrc, .profile
- Execute malicious commands on user login or shell initialization
- Difficult to detect as these files are regularly modified

**T1546.008: Accessibility Features**
- Replace accessibility binaries (sethc.exe, utilman.exe, osk.exe) with cmd.exe
- Access via Sticky Keys (5x Shift) or Utility Manager at login screen
- Provides SYSTEM-level access without authentication
- Works even when system is locked

**T1546.010: AppInit DLLs**
- Load malicious DLLs into every process via AppInit_DLLs registry key
- HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs
- Disabled by default with Secure Boot but can be re-enabled

**T1546.011: Application Shimming**
- Use Windows Application Compatibility framework to inject DLLs
- Shim database files (.sdb) installed to redirect function calls
- Can be used to bypass security controls and maintain persistence

**T1546.012: Image File Execution Options Injection (IFEO)**
- Set debugger value for legitimate executables in IFEO registry key
- When the target program is launched, the debugger program runs instead
- HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options

**T1546.013: PowerShell Profile**
- Modify PowerShell profile scripts to execute on PowerShell launch
- Locations: $PROFILE (current user), $PSHOME\\Profile.ps1 (all users)
- Effective against administrators who frequently use PowerShell

**T1546.015: Component Object Model Hijacking**
- Register malicious COM objects to replace or supplement legitimate ones
- Modify CLSID registry entries to load malicious DLLs
- Triggered when applications reference the hijacked COM objects

**T1546.016: Installer Packages**
- Abuse Windows Installer (msiexec) custom actions
- Modify MSI packages to include malicious payloads
- Runs with elevated privileges if package requires them

**Detection Strategies:**
- Registry monitoring for changes to IFEO, AppInit_DLLs, file associations, COM objects
- Monitor WMI event subscription creation (Event ID 5861)
- File integrity monitoring on shell configuration files and PowerShell profiles
- Monitor for replacement of accessibility feature binaries
- Track sdbinst.exe execution for shim database installation
- Baseline and monitor for changes to screensaver settings
- Monitor for msiexec.exe with unusual command-line parameters

**Mitigations:**
- M1038: Execution Prevention — application allowlisting
- M1022: Restrict File and Directory Permissions — protect shell configs, system binaries
- M1024: Restrict Registry Permissions — protect persistence-related keys
- M1028: Operating System Configuration — disable WMI event subscriptions where not needed
- Enable Secure Boot to restrict AppInit_DLLs
- Monitor and restrict COM object registration

## T1547: Boot or Logon Autostart Execution

**Technique Description:** Adversaries configure system settings to automatically execute a program during boot or logon to maintain persistence.

**T1547.001: Registry Run Keys / Startup Folder**
- Add entries to Run/RunOnce registry keys
- HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
- HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
- Place executables in Startup folders
- Most common Windows persistence mechanism

**T1547.003: Time Providers**
- Register malicious DLL as Windows time provider
- Loaded by svchost.exe with SYSTEM privileges
- Registered via W32Time service configuration

**T1547.004: Winlogon Helper DLL**
- Modify Winlogon registry entries to load malicious DLLs at logon
- Shell, Userinit, and Notify subkeys frequently abused
- Executes with SYSTEM privileges during logon

**T1547.006: Kernel Modules and Extensions**
- Load malicious kernel modules on Linux (insmod, modprobe)
- Load kernel extensions on macOS (legacy, restricted in modern versions)
- Provides kernel-level persistence and privilege

**T1547.009: Shortcut Modification**
- Modify existing shortcuts to execute malicious payloads before/alongside legitimate apps
- Add malicious arguments to LNK files
- Place malicious LNK files in Startup folder

**T1547.012: Print Processors**
- Register malicious DLL as a print processor
- Loaded by the spooler service (spoolsv.exe)
- Executes with SYSTEM privileges

**T1547.014: Active Setup**
- Abuse Active Setup mechanism to execute commands on user logon
- HKLM\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components
- Executes once per user, often missed by security tools

**Detection Strategies:**
- Monitor Run key and Startup folder changes (Sysmon Event ID 12, 13, 14)
- Track DLL loading by critical system processes (winlogon.exe, svchost.exe)
- Monitor kernel module loading on Linux (Sysmon for Linux)
- Alert on new registry entries in autostart locations
- File integrity monitoring on startup directories
- Periodic comparison of autostart entries against baseline

**Mitigations:**
- M1024: Restrict Registry Permissions on autostart keys
- M1022: Restrict File and Directory Permissions on startup folders
- M1038: Execution Prevention — application allowlisting
- Secure Boot and driver signing enforcement
- Regular audit of autostart entries across the enterprise

## T1574: Hijack Execution Flow

**Technique Description:** Adversaries abuse the way operating systems run programs to load their own malicious code instead of or alongside legitimate code.

**T1574.001: DLL Search Order Hijacking**
- Place malicious DLL in a location searched before the legitimate DLL path
- Exploit applications that do not specify full DLL paths
- Common in applications installed to user-writable directories

**T1574.002: DLL Side-Loading**
- Place malicious DLL alongside legitimate application that loads it
- Exploit legitimate, signed applications to load unsigned malicious code
- Often used with renamed legitimate applications to evade detection

**T1574.004: Dylib Hijacking (macOS)**
- Exploit dylib search order on macOS
- Place malicious dylib in locations searched before legitimate library

**T1574.006: Dynamic Linker Hijacking (Linux)**
- Modify LD_PRELOAD or LD_LIBRARY_PATH to load malicious shared objects
- Inject into any process by preloading malicious libraries
- Modify /etc/ld.so.preload for system-wide injection

**T1574.011: Services Registry Permissions Weakness**
- Modify service registry entries that have weak permissions
- Change ImagePath to point to malicious executable
- Exploit misconfigured service ACLs

**T1574.012: COR_PROFILER (.NET)**
- Set COR_PROFILER environment variable to load malicious .NET profiler DLL
- Loaded into every .NET process on the system
- Executes with the privileges of the target process

**Detection Strategies:**
- Monitor for DLL loads from unusual or user-writable locations
- Detect unsigned DLLs loaded by signed applications
- Monitor LD_PRELOAD and LD_LIBRARY_PATH environment variable changes
- Track service registry modifications
- Alert on COR_PROFILER environment variable settings
- Baseline DLL load patterns for critical applications

**Mitigations:**
- M1013: Application Developer Guidance — use fully qualified DLL paths
- M1044: Restrict Library Loading — enable SafeDllSearchMode
- M1022: Restrict File and Directory Permissions — protect application directories
- M1024: Restrict Registry Permissions on service configuration keys
- Code signing enforcement for loaded libraries
- Implement DLL allowlisting where possible

## T1505: Server Software Component

**Technique Description:** Adversaries abuse legitimate extensible features of servers to establish persistence.

**T1505.003: Web Shell**
- Deploy malicious scripts to web server directories (ASPX, JSP, PHP)
- Provide remote command execution through HTTP requests
- Often deployed after exploiting web application vulnerabilities
- Can be highly obfuscated to evade detection
- Memory-resident web shells leave no file on disk

**T1505.004: IIS Components**
- Install malicious IIS modules or handlers
- Intercept and modify HTTP requests/responses
- Execute with application pool identity privileges

**T1505.005: Terminal Services DLL**
- Load malicious DLL via RDP terminal services
- Executes with SYSTEM privileges

**Detection Strategies:**
- File integrity monitoring on web server directories
- Monitor for new files in web-accessible directories
- Detect unusual process execution from web server processes
- Monitor IIS module installation (appcmd.exe, PowerShell IIS cmdlets)
- Network monitoring for web shell communication patterns
- Regular scanning of web directories for unauthorized files

**Mitigations:**
- M1042: Disable or Remove Feature — remove unnecessary server components
- M1018: User Account Management — restrict write access to web directories
- M1022: Restrict File and Directory Permissions on web server directories
- Implement application allowlisting on web servers
- Deploy Web Application Firewall (WAF) to detect web shell traffic
