## The MITRE Corporation ##

## Details ##

- Version: 1.0.2
- Date: 05-15-2024

## Dependencies ##

- Powershell
- Posh-SSH Powershell Module
    - Tested Version: 3.1.3
    - https://www.powershellgallery.com/packages/Posh-SSH/3.1.3
- VMware.VimAutomation.Core Powershell Module (Contained in VMware.PowerCLI)
    - Tested Version: '13.2.0.22643732'
    - https://developer.vmware.com/web/tool/13.2/vmware-powercli/
- ESX Shell Credentials to SSH into a Hypervisor stored in a PSCredential Object ($ESXLocalCredential)

## Caveats ##

- There is a known false positive condition when checking for rogue VMs. If a legitimate VM is in a state of vMotion when the hypervisor it is on is being processed by the script, it may flag that VM as rogue. In such cases:
	- Cross reference VMs detected as rogue with syslog data to determine if the VM may have been a state of vMotion when the script was run. If so, it may indicate a false positive
	- Re-run the script to see if the same VM is still being flagged as rogue, if so this is a stronger indication that it is a true positive result

## How to Use ##

### Use Case #1: ###
- You're already connected to a vCenter with PowerCLI and can grab a hypervisors VMHost object with 'Get-VMHost'
    - $VMHost - The "$VMHost = Get-VMHost 'Hostname'" object
    - $ESXLocalCredential - The PSCredential object to SSH into the ESXi host "$ESXLocalCredential = Get-Credential"

```
.\Invoke-HiddenVMQuery.ps1 -VMHost $VMHost -ESXLocalCredential $ESXLocalCredential
```

### Use Case #2: ###
- You need to connect to a single vCenter and run it against an array of VM Hosts
    - $VIServers - The string representation of a VIServer "$VIServers = 'vcenter.test.domain'"
    - $VICredential - The PSCredential object to connect to the VIServer "$VICredential = Get-Credential"
    - $ESXLocalCredential - The PSCredential account object to SSH into the ESXi hosts "$ESXLocalCredential = Get-Credential"
        - If this is a unique credential set for each hypervisor you're looping through Invoke-HiddenVMQuery should be run on a per host basis like 'Use Case #4'

```
.\Invoke-HiddenVMQuery.ps1 -VIServers $VIServers -VICredential $VICredential -ESXLocalCredential $ESXLocalCredential
```

### Use Case #3: ###
- You need to connect to a Multiple vCenter(s) and or standalone ESXi hosts
    - $VIServers - The Array of string representation of a VIServer
        - $VIServers = @()
        - $VIServers += 'vcenter.test.domain'
        - $VIServers += 'vcenter2.test.domain'
        - $VIServers += 'standaloneesx.test.domain'
    - $VICredential - The PSCredential object to connect to the VIServer "$VICredential = Get-Credential"
    - $ESXLocalCredential - The PSCredential account object to SSH into the ESXi hosts "$ESXLocalCredential = Get-Credential"
        - If this is a unique credential set for each hypervisor you're looping through Invoke-HiddenVMQuery should be run on a per host basis like 'Use Case #4'

```
.\Invoke-HiddenVMQuery.ps1 -VIServers $VIServers -VICredential $VICredential -ESXLocalCredential $ESXLocalCredential
```

### Use Case #4: ###
- You need to connect to a Multiple vCenter(s) and or standalone ESXi hosts and each hypervisor has a unique credential to be imported for SSH
    - $VIServers - The Array of string representation of a VIServer
        - $VIServers = @()
        - $VIServers += 'vcenter.test.domain'
        - $VIServers += 'vcenter2.test.domain'
        - $VIServers += 'standaloneesx.test.domain'
    - $VICredential - The PSCredential object to connect to the VIServer "$VICredential = Get-Credential"
    - $ESXLocalCredential - The PSCredential account object to SSH into the ESXi hosts "$ESXLocalCredential = Get-Credential"
        - This will be defined in the example below to address all the VMHosts individually

```
foreach ($VIServer in $VIServers) {
    $ConnectVIServer = Connect-VIServer -Server $VIServer -Credential $VICredential
    $VMHosts = $null
    $VMHosts = Get-VMHost
    foreach($VMHost in $VMHosts) {
        $ESXLocalCredential = $null
        $ESXLocalCredential = Get-Credential # Or what ever method you have to get the PSCredential Object
        .\Invoke-HiddenVMQuery.ps1 -VMHost $VMHost -ESXLocalCredential $ESXLocalCredential
    }
    $DisconnectVIServer = Disconnect-VIServer -Confirm:$false
}
```

## Example Outputs ##
- An example of the clean run is below:
```
PS C:\Users\jdoe> .\Invoke-HiddenVMQuery.ps1 -VIServers 'vcenter.test.domain' -VICredential $VICredential -ESXLocalCredential $ESXLocalCredential
esx-test-1.test.domain has no findings.
esx-test-2.test.domain has no findings.
PS C:\Users\jdoe>
```

- An example of a rogue vm is below:
```
PS C:\Users\jdoe> .\Invoke-HiddenVMQuery.ps1 -VIServers 'vcenter.test.domain' -VICredential $VICredential -ESXLocalCredential $ESXLocalCredential
Rogue VM: HIDDEN-VM found on esx-test-1.test.domain
esx-test-2.test.domain has no findings.
PS C:\Users\jdoe>
```

- An example of rogue vm persistence is below:
```
PS C:\Users\jdoe> .\Invoke-HiddenVMQuery.ps1 -VIServers 'vcenter.test.domain' -VICredential $VICredential -ESXLocalCredential $ESXLocalCredential
esx-test-1.test.domain: Persistence found - /etc/rc.local.d/./local.sh:/bin/vmx -x /vmfs/volumes/<id>/HIDDEN-VM/HIDDEN-VM.vmx
esx-test-2.test.domain has no findings.
PS C:\Users\jdoe>
```
