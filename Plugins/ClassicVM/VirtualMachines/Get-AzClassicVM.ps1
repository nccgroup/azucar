#Plugin extract about VM from Azure
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
        $AzureClassicVMConfig = $AzureObject.AzureConfig.AzureClassicVM
        $Section = $AzureObject.AzureSection
        Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzucarADGeneralTaskMessage -f "Virtual Machine", $bgRunspaceID, $PluginName, $AzureObject.TenantID) `
                                -Plugin $PluginName -IsHost -Color Green
        #Retrieve instance
        $Instance = $AzureObject.Instance
        #Retrieve Azure Resource Management Auth
        $RMAuth = $AzureObject.AzureConnections.ResourceManager
        #List All VM
        $ClassicVM = Get-AzSecRMObject -Instance $Instance -Authentication $RMAuth `
                           -Provider $AzureClassicVMConfig.Provider -Objectype "virtualMachines" -APIVersion $AzureClassicVMConfig.APIVersion -Verbosity $Verbosity
        
        #Get primary object
        $AllClassicVM = @()
        if($ClassicVM){
            foreach($VM in $ClassicVM){
                if($VM.name){
                    $AzureClassicVM = New-Object -TypeName PSCustomObject
                    $AzureClassicVM | Add-Member -type NoteProperty -name VMName -value $VM.name
                    $AzureClassicVM | Add-Member -type NoteProperty -name Location -value $VM.Location
                    $AzureClassicVM | Add-Member -type NoteProperty -name ResourceGroupName -value $VM.id.Split("/")[4]
                    $AzureClassicVM | Add-Member -type NoteProperty -name ResourceGroupName -value $VM.id.Split("/")[4]
                    $AzureClassicVM | Add-Member -type NoteProperty -name ProvisioningState -value $VM.Properties.provisioningState
                    $AzureClassicVM | Add-Member -type NoteProperty -name PowerState -value $VM.Properties.instanceView.powerState
                    $AzureClassicVM | Add-Member -type NoteProperty -name PrivateIPAddress -value $VM.Properties.instanceView.privateIpAddress
                    $AzureClassicVM | Add-Member -type NoteProperty -name PublicIPAddress -value (@($VM.Properties.instanceView.publicIpAddresses) -join ',')
                    $AzureClassicVM | Add-Member -type NoteProperty -name ComputerName -value $VM.Properties.instanceView.computerName
                    $AzureClassicVM | Add-Member -type NoteProperty -name PlatformGuestAgent -value $VM.Properties.hardwareProfile.platformGuestAgent
                    $AzureClassicVM | Add-Member -type NoteProperty -name VMType -value $VM.Properties.hardwareProfile.size
                    $AzureClassicVM | Add-Member -type NoteProperty -name OperatingSystem -value $VM.Properties.storageProfile.operatingSystemDisk.operatingSystem
                    #Add to list
                    $AllClassicVM+=$AzureClassicVM
                }

            }
        }
    }
    End{
        if($AllClassicVM){
            #Work with SyncHash
            $SyncServer.$($PluginName)=$AllClassicVM
            $AllClassicVM.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.ClassicVM')
            #Create custom object for store data
            $AllVM = New-Object -TypeName PSCustomObject
            $AllVM | Add-Member -type NoteProperty -name Section -value $Section
            $AllVM | Add-Member -type NoteProperty -name Data -value $AllClassicVM
            #Add VM data to object
            if($AllClassicVM){
                $ReturnPluginObject | Add-Member -type NoteProperty -name ClassicVM -value $AllVM
            }
        }
        else{
            Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzureADGeneralQueryEmptyMessage -f "Virtual Machine", $AzureObject.TenantID) `
                                -Plugin $PluginName -Verbosity $Verbosity -IsWarning
        }
    }