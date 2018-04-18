#Plugin extract information related from Resource Manager VM from Azure
[cmdletbinding()]
    Param (
            [Parameter(HelpMessage="Background Runspace ID")]
            [int]
            $bgRunspaceID,

            [Parameter(HelpMessage="Not used in this version")]
            [HashTable]
            $SyncServer,

            [Parameter(HelpMessage="Azure Object with valuable data")]
            [Object]
            $AzureObject,

            [Parameter(HelpMessage="Object to return data")]
            [Object]
            $ReturnPluginObject,

            [Parameter(HelpMessage="Verbosity Options")]
            [System.Collections.Hashtable]
            $Verbosity,

            [Parameter(Mandatory=$false, HelpMessage="Save message in log file")]
	        [Bool] $WriteLog

        )
    Begin{
        #Import Azure API
        $LocalPath = $AzureObject.LocalPath
        $API = $AzureObject.AzureAPI
        $Utils = $AzureObject.Utils
        . $API
        . $Utils

        #Import Localized data
        $LocalizedDataParams = $AzureObject.LocalizedDataParams
        Import-LocalizedData @LocalizedDataParams;
    }
    Process{
        $PluginName = $AzureObject.PluginName
        #Retrieve Section
        $Section = $AzureObject.AzureSection
        #Retrieve Config
        $AzureVMConfig = $AzureObject.AzureConfig.AzureVM
        Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzucarADGeneralTaskMessage -f "Virtual Machines", $bgRunspaceID, $PluginName, $AzureObject.TenantID) `
                            -Plugin $PluginName -IsHost -Color Green
        #Retrieve instance
        $Instance = $AzureObject.Instance
        #Retrieve Azure Resource Management Auth
        $RMAuth = $AzureObject.AzureConnections.ResourceManager
        $AllVMs = @()
        #List All Virtual Machines
        $VMs = Get-AzSecRMObject -Instance $Instance -Authentication $RMAuth `
                                 -Provider $AzureVMConfig.Provider -Objectype "virtualmachines" `
                                 -APIVersion $AzureVMConfig.APIVersion -Verbosity $Verbosity -WriteLog $WriteLog
        if($Vms){
            foreach($vm in $VMs){
                $AzureVM = New-Object -TypeName PSCustomObject
                $AzureVM | Add-Member -type NoteProperty -name VMName -value $vm.name
                $AzureVM | Add-Member -type NoteProperty -name resourceGroupName -value $vm.id.Split("/")[4]
                $AzureVM | Add-Member -type NoteProperty -name Location -value $vm.location
                $AzureVM | Add-Member -type NoteProperty -name VMID -value $vm.properties.vmId
                $AzureVM | Add-Member -type NoteProperty -name Type -value $vm.properties.hardwareProfile.vmSize
                $AzureVM | Add-Member -type NoteProperty -name osType -value $vm.properties.storageprofile.osDisk.osType
                $AzureVM | Add-Member -type NoteProperty -name osOffer -value ("{0} {1}" -f $vm.properties.storageprofile.imageReference.offer, $vm.properties.storageprofile.imageReference.sku)
                $AzureVM | Add-Member -type NoteProperty -name adminusername -value $vm.properties.osprofile.adminUsername
                $AzureVM | Add-Member -type NoteProperty -name VMAgent -value $vm.properties.osprofile.windowsConfiguration.provisionVMAgent
                $AzureVM | Add-Member -type NoteProperty -name EnableAutomaticUpdates -value $vm.properties.osprofile.windowsConfiguration.enableAutomaticUpdates
                if($vm.properties.storageprofile.osDisk.encryptionSettings.enabled){
                    $AzureVM | Add-Member -type NoteProperty -name encryptionsettingsenabled -value "Enabled"
                }
                else{
                    $AzureVM | Add-Member -type NoteProperty -name encryptionsettingsenabled -value "DisabledFromKeyVault"
                }
                $NetworkInterface = $vm.properties.networkprofile.networkInterfaces.id
                Write-AzucarMessage -WriteLog $WriteLog -Message ("Get Network Interfaces for {0}..." -f $vm.name) `
                                    -Plugin $PluginName -Verbosity $Verbosity -IsVerbose
                
                $URI = ('{0}{1}?api-version={2}' -f $Instance.ResourceManager, $NetworkInterface, '2016-03-30')
                #Perform Query
                $Result = Get-AzSecRMObject -Manual -OwnQuery $URI -Authentication $RMAuth -Verbosity $Verbosity
                if($Result.name){
                    $AzureVM | Add-Member -type NoteProperty -name InterfaceName -value $Result.name
                    $AzureVM | Add-Member -type NoteProperty -name LocalIPAddress -value $Result.properties.ipConfigurations.properties.privateIPAddress  
                    $AzureVM | Add-Member -type NoteProperty -name MACAddress -value $Result.properties.macAddress 
                    $AzureVM | Add-Member -type NoteProperty -name IPForwardingEnabled -value $Result.properties.enableIPForwarding
                    $PublicIPEndPoint = $Result.properties.ipConfigurations.properties.publicIPAddress.id
                    $URI =  ('{0}{1}?api-version={2}' -f $Instance.ResourceManager, $PublicIPEndPoint, '2016-12-01')
                    Write-AzucarMessage -WriteLog $WriteLog -Message ("Get Public IPAddress for {0}..." -f $vm.name) `
                                    -Plugin $PluginName -Verbosity $Verbosity -IsVerbose
                    
                    $PublicIP = Get-AzSecRMObject -Manual -OwnQuery $URI -Authentication $RMAuth -Verbosity $Verbosity
                    if($PublicIP.properties){
                        $AzureVM | Add-Member -type NoteProperty -name PublicIPAddress -value $PublicIP.properties.ipAddress
                        $AzureVM | Add-Member -type NoteProperty -name publicIPAllocationMethod -value $PublicIP.properties.publicIPAllocationMethod                       
                    }
                }
                #Decorate Object
                $AzureVM.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.VirtualMachines')
                #Add VM to Array
                $AllVMs+= $AzureVM
                
            }
        }
    }
    End{
        if($AllVMs){
            #Work with SyncHash
            $SyncServer.$($PluginName)=$AllVMs
            $AllVMs.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.VirtualMachines')
            #Create custom object for store data
            $VirtualMachines = New-Object -TypeName PSCustomObject
            $VirtualMachines | Add-Member -type NoteProperty -name Section -value $Section
            $VirtualMachines | Add-Member -type NoteProperty -name Data -value $AllVMs
            #Return Object
            if($VirtualMachines){
                $ReturnPluginObject | Add-Member -type NoteProperty -name VirtualMachines -value $VirtualMachines
            }
        }
        else{
            Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzureADGeneralQueryEmptyMessage -f "Virtual Machines", $AzureObject.TenantID) `
                                -Plugin $PluginName -Verbosity $Verbosity -IsWarning
        }
    }