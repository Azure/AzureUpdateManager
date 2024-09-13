param(
    [switch]$returnCompactFormat,
    [switch]$returnAsJson
)

function New-RuleCheckResult
{
    [CmdletBinding()]
    param(
        [string][Parameter(Mandatory=$true)]$ruleId,
        [string]$ruleName,
        [string]$ruleDescription,
        [string][ValidateSet("Passed","PassedWithWarning", "Failed", "Information")]$result,
        [string]$resultMessage,
        [string]$ruleGroupId = $ruleId,
        [string]$ruleGroupName,
        [string]$resultMessageId = $ruleId,
        [array]$resultMessageArguments = @()
    )

    if ($returnCompactFormat.IsPresent) {
        $compactResult = [pscustomobject] [ordered] @{
            'RuleId'= $ruleId
            'RuleGroupId'= $ruleGroupId
            'CheckResult'= $result
            'CheckResultMessageId'= $resultMessageId
            'CheckResultMessageArguments'= $resultMessageArguments
        }
        return $compactResult
    }

    $fullResult = [pscustomobject] [ordered] @{
        'RuleId'= $ruleId
        'RuleGroupId'= $ruleGroupId
        'RuleName'= $ruleName
        'RuleGroupName' = $ruleGroupName
        'RuleDescription'= $ruleDescription
        'CheckResult'= $result
        'CheckResultMessage'= $resultMessage
        'CheckResultMessageId'= $resultMessageId
        'CheckResultMessageArguments'= $resultMessageArguments
    }
    return $fullResult
}

function checkRegValue
{
    [CmdletBinding()]
    param(
        [string][Parameter(Mandatory=$true)]$path,
        [string][Parameter(Mandatory=$true)]$name,
        [int][Parameter(Mandatory=$true)]$valueToCheck
    )

    $val = Get-ItemProperty -path $path -name $name -ErrorAction SilentlyContinue
    if($val.$name -eq $null) {
        return $null
    }

    if($val.$name -eq $valueToCheck) {
        return $true
    } else {
        return $false
    }
}

function getRegValue {
    [CmdletBinding()]
    param(
        [string][Parameter(Mandatory = $true)]$path,
        [string][Parameter(Mandatory = $true)]$name
    )

    $val = Get-ItemProperty -path $path -name $name -ErrorAction SilentlyContinue
    if ($val.$name -eq $null) {
        return $null
    }
    return $val.$name
}

function Validate-OperatingSystemSupported {
    $osRequirementsLink = "https://learn.microsoft.com/en-us/azure/update-manager/support-matrix?tabs=azurearc-os%2Cpublic%2Cthird-party-win"

    $ruleId = "OSSupportedCheck"
    $ruleName = "Operating system supported check"
    $ruleDescription = "The Windows Operating system must be version 6.1.7601 (Windows Server 2008 R2 SP1) or higher."
    $result = $null
    $resultMessage = $null
    $ruleGroupId = "prerequisites"
    $ruleGroupName = "Prerequisites Checks"
    $resultMessageArguments = @()

    if([System.Environment]::OSVersion.Version -ge [System.Version]"6.3.9600") {
        $result = "Passed"
        $resultMessage = "Operating System version is supported."
    } else {
        $result = "Failed"
        $resultMessage = "Operating System version is not supported. Supported versions listed here: $osRequirementsLink."
        $resultMessageArguments += $osRequirementsLink
    }
    $resultMessageId = "$ruleId.$result"

    return New-RuleCheckResult $ruleId $ruleName $ruleDescription $result $resultMessage $ruleGroupId $ruleGroupName $resultMessageId $resultMessageArguments
}

function Validate-DotNetFrameworkInstalled {
    $netFrameworkDownloadLink = "https://dotnet.microsoft.com/en-us/download/dotnet-framework"

    $ruleId = "DotNetFrameworkInstalledCheck"
    $ruleName = "Dot Net Framework installation check"
    $ruleDescription = ".NET Framework version 4.0 or higher is required."
    $result = $null
    $resultMessage = $null
    $ruleGroupId = "prerequisites"
    $ruleGroupName = "Prerequisites Checks"
    $resultMessageArguments = @()

    # https://docs.microsoft.com/dotnet/framework/migration-guide/how-to-determine-which-versions-are-installed
    $dotNetFullRegistryPath = "HKLM:SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full"
    if((Get-ChildItem $dotNetFullRegistryPath -ErrorAction SilentlyContinue) -ne $null) {
        $versionCheck = (Get-ChildItem $dotNetFullRegistryPath) | Get-ItemPropertyValue -Name Release | ForEach-Object { $_ -ge 378389 }
        if($versionCheck -eq $true) {
            $result = "Passed"
            $resultMessage = ".NET Framework version 4.0+ is found"
        } else {
            $result = "Failed"
            $resultMessage = ".NET Framework version 4.0 or higher is required: $netFrameworkDownloadLink."
            $resultMessageArguments += $netFrameworkDownloadLink
        }
    } else{
        $result = "Failed"
        $resultMessage = ".NET Framework version 4.0 or higher is required: $netFrameworkDownloadLink."
        $resultMessageArguments += $netFrameworkDownloadLink
    }
    $resultMessageId = "$ruleId.$result"

    return New-RuleCheckResult $ruleId $ruleName $ruleDescription $result $resultMessage $ruleGroupId $ruleGroupName $resultMessageId $resultMessageArguments
}

function Validate-TLSVersion {
    $ruleId = "TlsVersionCheck"
    $ruleName = "TLS version check"
    $ruleDescription = "Client and Server connections must support TLS 1.2."
    $result = $null
    $reason = ""
    $resultMessage = $null
    $ruleGroupId = "prerequisites"
    $ruleGroupName = "Prerequisites Checks"

    $tls12RegistryPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.2\\"
    $serverEnabled =     checkRegValue ([System.String]::Concat($tls12RegistryPath, "Server")) "Enabled" 1
    $serverNotDisabled = checkRegValue ([System.String]::Concat($tls12RegistryPath, "Server")) "DisabledByDefault" 0
    $clientEnabled =     checkRegValue ([System.String]::Concat($tls12RegistryPath, "Client")) "Enabled" 1
    $clientNotDisabled = checkRegValue ([System.String]::Concat($tls12RegistryPath, "Client")) "DisabledByDefault" 0

    $serverNotEnabled = checkRegValue ([System.String]::Concat($tls12RegistryPath, "Server")) "Enabled" 0
    $serverDisabled =   checkRegValue ([System.String]::Concat($tls12RegistryPath, "Server")) "DisabledByDefault" 1
    $clientNotEnabled = checkRegValue ([System.String]::Concat($tls12RegistryPath, "Client")) "Enabled" 0
    $clientDisabled =   checkRegValue ([System.String]::Concat($tls12RegistryPath, "Client")) "DisabledByDefault" 1

    if ($validationResults[0].CheckResult -ne "Passed" -and [System.Environment]::OSVersion.Version -ge [System.Version]"6.0.6001") {
        $result = "Failed"
        $resultMessageId = "$ruleId.$result"
        $resultMessage = "Enable TLS 1.2 on your operating system. Follow the instructions to enable it: https://support.microsoft.com/help/4019276/update-to-add-support-for-tls-1-1-and-tls-1-2-in-windows."
    } elseif([System.Environment]::OSVersion.Version -ge [System.Version]"6.1.7601" -and [System.Environment]::OSVersion.Version -le [System.Version]"6.1.8400") {
        if($clientNotDisabled -and $serverNotDisabled -and !($serverNotEnabled -and $clientNotEnabled)) {
            $result = "Passed"
            $resultMessage = "TLS 1.2 is enabled on the Operating System"
            $resultMessageId = "$ruleId.$result"
        } else {
            $result = "Failed"
            $reason = "NotExplicitlyEnabled"
            $resultMessageId = "$ruleId.$result.$reason"
            $resultMessage = "Enable TLS 1.2 on your operating system. Follow the instructions to enable it: https://docs.microsoft.com/windows-server/security/tls/tls-registry-settings#tls-12."
        }
    } elseif([System.Environment]::OSVersion.Version -ge [System.Version]"6.2.9200") {
        if($clientDisabled -or $serverDisabled -or $serverNotEnabled -or $clientNotEnabled) {
            $result = "Failed"
            $reason = "ExplicitlyDisabled"
            $resultMessageId = "$ruleId.$result.$reason"
            $resultMessage = "TLS 1.2 is available on the Operating System, but currently disabled. Follow the instructions to re-enable: https://docs.microsoft.com/windows-server/security/tls/tls-registry-settings#tls-12."
        } else {
            $result = "Passed"
            $reason = "EnabledByDefault"
            $resultMessageId = "$ruleId.$result.$reason"
            $resultMessage = "TLS 1.2 is enabled on the Operating System."
        }
    } else {
        $result = "Failed"
        $reason = "NoDefaultSupport"
        $resultMessageId = "$ruleId.$result.$reason"
        $resultMessage = "Your OS does not support TLS 1.2."
    }
    return New-RuleCheckResult $ruleId $ruleName $ruleDescription $result $resultMessage $ruleGroupId $ruleGroupName $resultMessageId
}

function Validate-ServiceStatus {
    [CmdletBinding()]
    param(
        [string][Parameter(Mandatory=$true)]$service,
        [string][Parameter(Mandatory=$true)]$ruleId,
        [string][Parameter(Mandatory=$true)]$ruleName,
        [string]$ruleDescription = "Azure Arc Agent related services must be running to ensure proper working of the arc agent."
    )

    $result = $null
    $resultMessage = $null
    $ruleGroupId = "arcagentservices"
    $ruleGroupName = "Azure Arc Agent Checks"
    $resultMessageArguments = @()

    $serviceObj = Get-Service -Name $service -ErrorAction SilentlyContinue
    if ($null -ne $serviceObj -and $serviceObj.Status -eq 'Running') {
        $result = "Passed"
        $resultMessage = "$service is running."
    } else {
        $result = "Failed"
        $resultMessage = "$service is not running."
    }
    $resultMessageId = "$ruleId.$result"
    return New-RuleCheckResult $ruleId $ruleName $ruleDescription $result $resultMessage $ruleGroupId $ruleGroupName $resultMessageId $resultMessageArguments
}

function Validate-AzureArcAgentServices { 
    $services = @(
        @{
            "service" = "himds";
            "ruleId" = "HimdsServiceCheck";
            "ruleName" = "Hybrid Instance Metadata service (himds) check"
        }
    )
    
    # Validate Service Status for each service
    foreach ($service in $services) {
        Validate-ServiceStatus $service.service $service.ruleId $service.ruleName
    }
}

function Is-EndpointReachable {
    [CmdletBinding()]
    param(
        [string][Parameter(Mandatory=$true)]$endpoint
    )

    try {
        if((Test-NetConnection -ComputerName $endpoint -Port 443 -WarningAction SilentlyContinue).TcpTestSucceeded) {
            $result = "Passed"
        } else {
            $result = "Failed"
        }
    }
    catch {
        $client = New-Object Net.Sockets.TcpClient
        try {
            $client.Connect($endpoint, 443)
            $result = "Passed"
        } catch {
            $result = "Failed"
        } finally {
            $client.Dispose()
        }
    }

    return $result
}

function Validate-AzureArcEndpointConnectivity {
    $endpoints = @(
        "login.microsoftonline.com",
        "management.azure.com",
        "agentserviceapi.guestconfiguration.azure.com",
        "gbl.his.arc.azure.com"
    )

    # Validate connectivity for each endpoint
    $failedEndpoints = @()
    foreach ($endpoint in $endpoints) {
        $result = Is-EndpointReachable $endpoint
        if ($result -eq "Failed") {
            $failedEndpoints += $endpoint
        }
    }

    $ruleId = "ArcRequiredEndpointsCheck"
    $ruleName = "AAzure arc required endpoints connectivity check"
    $ruleDescription = "Proxy and firewall configuration must allow the system to communicate with Azure arc required endpoints."
    $result = if ($failedEndpoints.Count -eq 0) { "Passed" } else { "Failed" }
    $resultMessage = if ($failedEndpoints.Count -eq 0) { "All endpoints are reachable." } else { "Failed to reach the following endpoints: $($failedEndpoints -join ', ')" }
    $ruleGroupId = "connectivity"
    $ruleGroupName = "Connectivity Checks"
    $resultMessageId = "$ruleId.$result"
    $resultMessageArguments = $failedEndpoints

    return New-RuleCheckResult $ruleId $ruleName $ruleDescription $result $resultMessage $ruleGroupId $ruleGroupName $resultMessageId $resultMessageArguments
}
function Validate-WindowsUpdateEndpointConnectivity {
    param(
        [string[]]$endpoints = @(
            "windowsupdate.microsoft.com",
            "dl.delivery.mp.microsoft.com",
            "download.windowsupdate.com",
            "download.microsoft.com",
            "ntservicepack.microsoft.com",
            "go.microsoft.com",
            "dl.delivery.mp.microsoft.com"
        )
    )

    $failedEndpoints = @()
    foreach ($endpoint in $endpoints) {
        $result = Is-EndpointReachable $endpoint
        if ($result -eq "Failed") {
            $failedEndpoints += $endpoint
        }
    }

    $ruleId = "WUEndpointConnectivityCheck"
    $ruleName = "Windows update endpoints connectivity check"
    $ruleDescription = "Proxy and firewall configuration must allow the system to communicate with Windows Update endpoints."
    $result = if ($failedEndpoints.Count -eq 0) { "Passed" } else { "Failed" }
    $resultMessage = if ($failedEndpoints.Count -eq 0) { "All endpoints are reachable." } else { "Failed to reach the following endpoints: $($failedEndpoints -join ', ')" }
    $ruleGroupId = "connectivity"
    $ruleGroupName = "Connectivity Checks"
    $resultMessageId = "$ruleId.$result"
    $resultMessageArguments = $failedEndpoints

    return New-RuleCheckResult $ruleId $ruleName $ruleDescription $result $resultMessage $ruleGroupId $ruleGroupName $resultMessageId $resultMessageArguments
}

function Validate-AlwaysAutoRebootEnabled {
    $ruleId = "AlwaysAutoRebootCheck"
    $ruleName = "Automatic reboot check"
    $ruleDescription = "Automatic reboot should not be enabled as it forces a reboot irrespective of update configuration."
    $result = $null
    $resultMessage = $null
    $ruleGroupId = "machinesettings"
    $ruleGroupName = "Machine Update Settings Checks"

    $automaticUpdatePath = "HKLM:\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU"
    $rebootEnabledBySchedule = checkRegValue ($automaticUpdatePath) "AlwaysAutoRebootAtScheduledTime" 1
    $rebootEnabledByDuration = getRegValue ($automaticUpdatePath) "AlwaysAutoRebootAtScheduledTimeMinutes"


    if (  $rebootEnabledBySchedule -or $rebootEnabledByDuration ) {
        $result = "PassedWithWarning"
        $resultMessage = "Windows Update reboot registry keys are set to automatic reboot and this can cause unexpected reboots on your machine when installing updates."
    }
    else {
        $result = "Passed"
        $resultMessage = "Windows Update reboot registry keys are not set to automatic reboot."

    }
    $resultMessageId = "$ruleId.$result"
    return New-RuleCheckResult $ruleId $ruleName $ruleDescription $result $resultMessage $ruleGroupId $ruleGroupName $resultMessageId $resultMessageArguments
}

function Validate-AutomaticUpdateEnabled {
    $ruleId = "AutomaticUpdateCheck"
    $ruleName = "Automatic update check"
    $ruleDescription = "Automatic Update should not be enabled on the machine."
    $result = $null
    $resultMessage = $null
    $ruleGroupId = "machinesettings"
    $ruleGroupName = "Machine Update Settings Checks"

    $automaticUpdatePath = "HKLM:\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU"
    $autoUpdateEnabled = checkRegValue ($automaticUpdatePath) "AUOptions" 4


    if ( $autoUpdateEnabled ) {
        $result = "PassedWithWarning"
        $resultMessage = "Windows Update will automatically download and install new updates as they become available."
    }
    else {
        $result = "Passed"
        $resultMessage = "Windows Update is not set to automatically install updates as they become available."

    }
    $resultMessageId = "$ruleId.$result"
    return New-RuleCheckResult $ruleId $ruleName $ruleDescription $result $resultMessage $ruleGroupId $ruleGroupName $resultMessageId $resultMessageArguments
}

function Validate-WSUSServerConfigured {
    $ruleId = "WSUSServerConfiguredCheck"
    $ruleName = "WSUS server configured check"
    $ruleDescription = "Increase awareness on WSUS configured on the server."
    $result = $null
    $resultMessage = $null
    $ruleGroupId = "machinesettings"
    $ruleGroupName = "Machine Update Settings Checks"

    $automaticUpdatePath = "HKLM:\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate"
    $wsusServerConfigured = getRegValue ($automaticUpdatePath) "WUServer"

    if ( $null -ne $wsusServerConfigured ) {
        $result = "PassedWithWarning"
        $resultMessage = "Windows Updates are downloading from a configured WSUS Server $wsusServerConfigured."
        $resultMessageArguments = @() + $wsusServerConfigured
    }
    else {
        $result = "Passed"
        $resultMessage = "Windows Updates are downloading from the default Windows Update location."
    }
    $resultMessageId = "$ruleId.$result"
    return New-RuleCheckResult $ruleId $ruleName $ruleDescription $result $resultMessage $ruleGroupId $ruleGroupName $resultMessageId $resultMessageArguments
}

function Validate-HttpsConnection {
    $ruleId = "HttpsConnectionCheck"
    $ruleName = "Https connection check"
    $result = $null
    $resultMessage = $null
    $ruleGroupId = "prerequisites"
    $ruleGroupName = "Prerequisites Checks"
    $endpoint = "login.microsoftonline.com"
    $resultMessageArguments = @() + $endpoint

    $result = Is-EndpointReachable $endpoint
    if($result -eq "Passed") {
        $resultMessage = "Machine is able to make https requests."
    } else {
        $resultMessage = "Machine is not able to make https requests."
    }

    $resultMessageId = "$ruleId.$result"

    return New-RuleCheckResult $ruleId $ruleName $ruleDescription $result $resultMessage $ruleGroupId $ruleGroupName $resultMessageId $resultMessageArguments
}


function Validate-ProxySettings {
    $ruleId = "ProxySettingsCheck"
    $ruleName = "Proxy settings check"
    $ruleDescription = "Check if Proxy is enabled on the VM."
    $result = $null
    $resultMessage = ""
    $ruleGroupId = "prerequisites"
    $ruleGroupName = "Prerequisites Checks"
    $resultMessageId = ""
    $resultMessageArguments = @()

    $res = netsh winhttp show proxy
    if ($res -like '*Direct access*') {
        $result = "Passed"
        $resultMessage = "Proxy is not set."
    } else {
        $result = "PassedWithWarning"
        $resultMessage = "Proxy is set."
    }

    $resultMessageId = "$ruleId.$result"
    return New-RuleCheckResult $ruleId $ruleName $ruleDescription $result $resultMessage $ruleGroupId $ruleGroupName $resultMessageId $resultMessageArguments
}

function Validate-WUIsEnabled {
    $windowsServiceName = "wuauserv"
    $windowsServiceDisplayName = "Windows Update"

    $ruleId = "WUServiceRunningCheck"
    $ruleName = "Windows Update service must be running"
    $ruleDescription = "Windows update service must not be in the disabled state."
    $result = $null
    $resultMessage = $null
    $ruleGroupId = "machinesettings"
    $ruleGroupName = "Machine Update Settings"
    $resultMessageArguments = @()

    if(Get-Service -Name $windowsServiceName -ErrorAction SilentlyContinue | select -property name,starttype | Where-Object {$_.StartType -eq "Disabled"} | Select-Object) {
        $result = "Failed"
        $resultMessage = "$windowsServiceDisplayName service ($windowsServiceName) is disabled. Please set it to automatic or manual. You can run 'sc config wuauserv start= demand' to set it to manual."
    } else {
        $result = "Passed"
        $resultMessage = "$windowsServiceDisplayName service ($windowsServiceName) is running."
    }
    $resultMessageId = "$ruleId.$result"

    return New-RuleCheckResult $ruleId $ruleName $ruleDescription $result $resultMessage $ruleGroupId $ruleGroupName $resultMessageId $resultMessageArguments
}

function Validate-MUIsEnabled {
    $ruleId = "MUEnableCheck"
    $ruleName = "Microsoft Update enabled check"
    $ruleDescription = "Microsoft Update must be running to receive updates for Microsoft Products."
    $result = $null
    $reason = ""
    $resultMessage = $null
    $ruleGroupId = "machinesettings"
    $ruleGroupName = "Machine Update Settings"
    $resultMessageArguments = @()

    # Create a COM object to interact with the Windows Update Agent API
    $updateServiceManager = New-Object -ComObject "Microsoft.Update.ServiceManager"

    # Get the services added to the WUA
    $services = $updateServiceManager.Services

    # Check if Microsoft Update (MU) is among the services
    $muRegistered = $services | Where-Object { $_.ServiceID -eq "7971f918-a847-4430-9279-4a52d1efe18d" }

    if ($muRegistered) {
        # Now check registry to see if MU is enabled
        $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Services\7971f918-a847-4430-9279-4a52d1efe18d"
        $registryValueName = "RegisteredWithAU"
        $registeredWithAU = Get-ItemProperty -Path $registryPath -Name $registryValueName -ErrorAction SilentlyContinue

        if ($registeredWithAU -and $registeredWithAU.RegisteredWithAU -eq 1) {
            $result = "Passed"
            $resultMessage = "Microsoft Update is registered with Windows Update and enabled."
            $resultMessageId = "$ruleId.$result"
        } else {
            $result = "PassedWithWarning"
            $reason = "MURegisteredButDisabled"
            $resultMessage = "Microsoft Update is registered with Windows Update but disabled. Please enable Microsoft Update to receive updates for Microsoft Products."
            $resultMessageId = "$ruleId.$result.$reason"
        }
    } else {
        $result = "PassedWithWarning"
        $resultMessage = "Microsoft Update is disabled. Please enable Microsoft Update to receive updates for Microsoft Products."
        $resultMessageId = "$ruleId.$result"
    }

    return New-RuleCheckResult $ruleId $ruleName $ruleDescription $result $resultMessage $ruleGroupId $ruleGroupName $resultMessageId $resultMessageArguments
}

$validationResults = @()
$validationResults += Validate-OperatingSystemSupported
$validationResults += Validate-DotNetFrameworkInstalled
$validationResults += Validate-TLSVersion
$validationResults += Validate-HttpsConnection
$validationResults += Validate-ProxySettings
$validationResults += Validate-AzureArcEndpointConnectivity
$validationResults += Validate-AzureArcAgentServices
$validationResults += Validate-WSUSServerConfigured
if($null -ne $validationResults[-1] -and $validationResults[-1].CheckResult -eq "Passed") {
    $validationResults += Validate-WindowsUpdateEndpointConnectivity
}
$validationResults += Validate-AlwaysAutoRebootEnabled
$validationResults += Validate-AutomaticUpdateEnabled
$validationResults += Validate-WUIsEnabled
$validationResults += Validate-MUIsEnabled

if($returnAsJson.IsPresent) {
    return ConvertTo-Json $validationResults -Compress
} else {
    return $validationResults
}