### THE MITRE Corporation

param (
    [Parameter(Mandatory=$false)]
    [string[]]$VIServers,
    [Parameter(Mandatory=$false)]
    [string]$VIPort = '443',
    [parameter(Mandatory=$false)]
    [psobject]$VICredential,
    [parameter(Mandatory=$True)]
    [psobject]$ESXLocalCredential,
    [parameter(Mandatory=$false)]
    [psobject]$VMHost
)

### Please read the README.md before moving forward.
### This script will be used to identify rogue VM processes and possible VM persistence through rc.local.d on a hypervisor

begin {
    Import-Module -Name "VMware.VimAutomation.Core" -MinimumVersion  '13.2.0.22643732'
    Import-Module -Name 'Posh-SSH' -MinimumVersion '3.1.3'
    $Report = @()
} process {
    if($VIServers -and $VICredential) {
        $Connections = @()
        foreach ($VI in $VIServers) {
            Write-Verbose -Message "Connecting to $VI Server"
            try {
                $Connections += Connect-VIServer $VI -Port $VIPort -NotDefault -Credential $VICredential -ErrorAction 'Stop'
            } catch {
                Write-Verbose -Message "No ESXi/vCenter connection"
                $Report += Write-Output -InputObject "Failed to Connect to $VI"
            }
        }
    }
    $VMHosts = @()
    if(!$VMHost){
        if($Connections) {
            foreach($Connection in $Connections) {
                $VMHosts += Get-VMHost -Server $Connection -State 'Connected'
            }
        } else {
            if($global:DefaultVIServer) {
                $VMHosts = Get-VMHost -State 'Connected'
            } else {
                throw "No VIServers are connected"
            }
        }
    } else {
        $VMHosts += $VMHost
    }
    try {
        $StartSSH = $VMHosts | Get-VMHostService | Where-Object {$_.Label -eq "SSH"} | Start-VMHostService -Confirm:$False
    } catch {
        $Report += Write-Output -InputObject "Ran into an issue starting SSH."
    }

    foreach($VMHost in $VMHosts){
        $SetLockdown = $false
        $LockdownCheck = $null
        $LockdownCheck = $VMHost | Select-Object Name,@{N="Lockdown";E={$_.Extensiondata.Config.LockdownMode}}
        If($LockdownCheck.Lockdown -ne 'lockdownDisabled'){
            $lockdown = (Get-View $VMHost).ExitLockdownMode()
            $SetLockdown = $true
        }
        Try {
            $Session = $null
            $Id = $null
            $Session = New-SSHSession -ComputerName $VMHost.Name -Credential $ESXLocalCredential -AcceptKey -Force -WarningAction 'SilentlyContinue'
            $Id = $Session.SessionId
            $Processes = (Invoke-SshCommand -SessionId $ID -Command "esxcli vm process list").Output
            $Registers = (Invoke-SshCommand -Session $ID -Command "vim-cmd vmsvc/getallvms").Output
            $VMXQuery = (Invoke-SshCommand -Session $ID -Command "grep -r 'vmx' /etc/rc.local.d/.").Output
            $VMProcesses = $Processes | Where-Object{$_[0] -ne ' ' -and $_[0]}
            $RogueVMs = $VMProcesses | Where-Object{!(Select-String -InputObject $Registers -Pattern $_ -SimpleMatch)}
            if($RogueVMs) {
                foreach($RogueVM in $RogueVMs) {
                    $Report += Write-Output -InputObject "Rogue VM: $($RogueVM) found on $($VMHost.Name)"
                }
            }
            if($VMXQuery) {
                foreach($Finding in $VMXQuery) {
                    $Report += Write-Output -InputObject ($VMHost.Name + ": Persistence found - " + $Finding)
                }
            }
            if(!$RogueVMs -and !$VMXQuery) {
                $Report += Write-Output -InputObject ($VMHost.Name + ' has no findings.')
            }
        } Catch {
            $Report += Write-Output -InputObject ($VMHost.Name + ' ran into an error likely establishing a remote connection. The Hypervisor could be offline.')
        } Finally {
            If($SetLockdown -eq $true){
                $lockdown = (Get-view $VMHost).EnterLockdownMode()
            }
        }
    }
    $StopSSH = $VMHosts | Get-VMHostService | Where-Object {$_.Label -eq "SSH"} | Stop-VMHostService -Confirm:$False
    if($Connections) {
        foreach($Connection in $Connections) {
            $Connection | Disconnect-VIServer -Confirm:$false
        }
    }
    if(!$Report) {
        Write-Output -InputObject "No findings."
    } else {
        Write-Output -InputObject $Report
    }
}
