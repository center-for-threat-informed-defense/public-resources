# MITRE: NERVE Incident

This directory contains indicators related to a cybersecurity incident at MITRE ("NERVE
incident") and a detection script for the "rogue VM" adversary technique observed during
that incident.

- [Getting Started](#getting-started)
- [Rogue VM Detection Script](#rogue-vm-detection-script)
  - [Dependencies](#dependencies)
  - [Caveats](#caveats)
  - [Known False Positives](#known-false-positives)
  - [Usage](#usage)
  - [Examples](#examples)
  - [Scan Results](#scan-results)
- [Notice](#notice)

## Getting Started

This incident has been publicly documented in a series of blog posts.

* [Advanced Cyber Threats Impact Even the Most Prepared](https://medium.com/mitre-engenuity/advanced-cyber-threats-impact-even-the-most-prepared-56444e980dc8)
* [Technical Deep Dive: Understanding the Anatomy of a Cyber Intrusion](https://medium.com/mitre-engenuity/technical-deep-dive-understanding-the-anatomy-of-a-cyber-intrusion-080bddc679f3)
* [Infiltrating Defenses: Abusing VMware in MITRE’s Cyber Intrusion](https://medium.com/mitre-engenuity/infiltrating-defenses-abusing-vmware-in-mitres-cyber-intrusion-4ea647b83f5b)

## Rogue VM Detection Script

**Name:** [Invoke-HiddenVMQuery.ps1](./Invoke-HiddenVMQuery.ps1)  
**Version:** 1.0.2  
**Release Date:** 2024-05-22  

### Dependencies

- PowerShell
- [Posh-SSH Module](https://www.powershellgallery.com/packages/Posh-SSH/3.1.3)
- [VMware.PowerCLI Module](https://developer.vmware.com/web/tool/13.2/vmware-powercli/)
  (Tested Version: 13.2.0.22643732)

### Caveats

🚨This script enables the SSH service on hypervisors in order to run shell commands. In normal operation, the script will disable the SSH service after it finishes running, but please take care to review SSH service status if this script encounters any errors (or if you intended to keep SSH service enabled).🚨

### Known False Positives

There is a known false positive condition when checking for rogue VMs. If a legitimate
VM is in a state of vMotion when the hypervisor it is on is being processed by the
script, it may flag that VM as rogue. In such cases:

* Cross reference VMs detected as rogue with syslog data to determine if the VM may have
  been in a state of vMotion when the script was run. If so, it may indicate a false
  positive
* Re-run the script to see if the same VM is still being flagged as rogue, if so this is
  a stronger indication that it is a true positive result

### Usage

| Parameter             | Required? | Type           | Description                                     |
| --------------------- | --------- | -------------- | ----------------------------------------------- |
| `-VIServers`          | No        | `string[]`     | Server name as a string.                        |
| `-VIPort`             | No        | `string`       | Port number to connect to vCenter (default 443) |
| `-VICredential`       | No        | `PSCredential` | Credential used to connect to vCenter.          |
| `-ESXLocalCredential` | Yes       | `PSCredential` | Credential used to SSH to a hypervisor.         |
| `-VMHost`             | No        | `VMHost`       | Reference to an ESX server.                     |

### Examples

**Example #1:**

You're already connected to a vCenter with PowerCLI and can grab a hypervisor `VMHost`
object with `Get-VMHost`.

```
$VMHost = Get-VMHost "<HOSTNAME>""
$ESXLocalCredential = Get-Credential
.\Invoke-HiddenVMQuery.ps1 -VMHost $VMHost -ESXLocalCredential $ESXLocalCredential
```

**Example #2:**

You need to connect to a single vCenter and run it against an array of VM Hosts using the same credential for each host. (If each host has different credentials, see Example 4.)

```
$VIServers = "<HOSTNAME>"
$VICredential = Get-Credential
$ESXLocalCredential = Get-Credential
.\Invoke-HiddenVMQuery.ps1 -VIServers $VIServers -VICredential $VICredential -ESXLocalCredential $ESXLocalCredential
```

**Example #3:**

You need to connect to a Multiple vCenter(s) and or standalone ESXi hosts.

```
$VIServers = @()
$VIServers += "vcenter.test.domain"
$VIServers += "vcenter2.test.domain"
$VIServers += "standaloneesx.test.domain"
$VICredential = Get-Credential
$ESXLocalCredential = Get-Credential
.\Invoke-HiddenVMQuery.ps1 -VIServers $VIServers -VICredential $VICredential -ESXLocalCredential $ESXLocalCredential
```

**Example #4:**

You need to connect to a Multiple vCenter(s) and or standalone ESXi hosts and each hypervisor has a unique credential.

```
$VIServers = @()
$VIServers += "vcenter.test.domain"
$VIServers += "vcenter2.test.domain"
$VIServers += "standaloneesx.test.domain"
$VICredential = Get-Credential
$ESXLocalCredential = Get-Credential

foreach ($VIServer in $VIServers) {
    $ConnectVIServer = Connect-VIServer -Server $VIServer -Credential $VICredential
    $VMHosts = $null
    $VMHosts = Get-VMHost
    foreach($VMHost in $VMHosts) {
        $ESXLocalCredential = $null
        $ESXLocalCredential = Get-Credential
        .\Invoke-HiddenVMQuery.ps1 -VMHost $VMHost -ESXLocalCredential $ESXLocalCredential
    }
    $DisconnectVIServer = Disconnect-VIServer -Confirm:$false
}
```

### Scan Results

If the script does not detect and rogue VMs, you will see output like the following:

```
PS C:\Users\jdoe> .\Invoke-HiddenVMQuery.ps1 -VIServers 'vcenter.test.domain' -VICredential $VICredential -ESXLocalCredential $ESXLocalCredential
esx-test-1.test.domain has no findings.
esx-test-2.test.domain has no findings.
```

If the script detects a rogue VM, it will display a message indicating the affected
hosts and the names of the rogue VMs.

```
PS C:\Users\jdoe> .\Invoke-HiddenVMQuery.ps1 -VIServers 'vcenter.test.domain' -VICredential $VICredential -ESXLocalCredential $ESXLocalCredential
Rogue VM: HIDDEN-VM found on esx-test-1.test.domain
esx-test-2.test.domain has no findings.
```

If the script detects one of the rogue VM persistence mechanisms, it will display a
message indicating which persistence mechanism was found and which host it was found on.

```
PS C:\Users\jdoe> .\Invoke-HiddenVMQuery.ps1 -VIServers 'vcenter.test.domain' -VICredential $VICredential -ESXLocalCredential $ESXLocalCredential
esx-test-1.test.domain: Persistence found - /etc/rc.local.d/./local.sh:/bin/vmx -x /vmfs/volumes/<id>/HIDDEN-VM/HIDDEN-VM.vmx
esx-test-2.test.domain has no findings.
```

## Notice

Copyright 2024 MITRE Engenuity. Approved for public release. Document number(s)
CT0117.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
file except in compliance with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under
the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied. See the License for the specific language governing
permissions and limitations under the License.
