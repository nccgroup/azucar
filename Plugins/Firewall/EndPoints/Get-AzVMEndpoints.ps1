#Plugin extract about EndPoints from Azure
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
        Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzucarADGeneralTaskMessage -f "Classic Endpoints", $bgRunspaceID, $PluginName, $AzureObject.TenantID) `
                                -Plugin $PluginName -IsHost -Color Green
        #Retrieve instance
        $Instance = $AzureObject.Instance
        #Retrieve Azure Resource Management Auth
        $RMAuth = $AzureObject.AzureConnections.ResourceManager
        #List All Classic VM
        $ClassicVM = Get-AzSecRMObject -Instance $Instance -Authentication $RMAuth `
                           -Provider $AzureClassicVMConfig.Provider -Objectype "virtualMachines" `
                           -APIVersion $AzureClassicVMConfig.APIVersion -Verbosity $Verbosity -WriteLog $WriteLog
        
        #Get primary object
        $AllClassicVM = @()
        if($ClassicVM){
            foreach($VM in $ClassicVM){
                $Endpoints = $VM.Properties.networkProfile.inputEndpoints            
                foreach ($Endpoint in $Endpoints){
                    $AzureClassicVM = New-Object -TypeName PSCustomObject
                    $AzureClassicVM | Add-Member -type NoteProperty -name VMName -value $VM.name
                    $AzureClassicVM | Add-Member -type NoteProperty -name EndPointName -value $EndPoint.EndPointName
                    $AzureClassicVM | Add-Member -type NoteProperty -name publicIpAddress -value $EndPoint.publicIpAddress
                    $AzureClassicVM | Add-Member -type NoteProperty -name privatePort -value $EndPoint.privatePort
                    $AzureClassicVM | Add-Member -type NoteProperty -name publicPort -value $EndPoint.publicPort
                    $AzureClassicVM | Add-Member -type NoteProperty -name protocol -value $EndPoint.protocol
                    $AzureClassicVM | Add-Member -type NoteProperty -name enableDirectServerReturn -value $EndPoint.enableDirectServerReturn
                    $AllClassicVM+=$AzureClassicVM
                }            
            }
        }
    }
    End{
        if($AllClassicVM){
            #Work with SyncHash
            $SyncServer.$($PluginName)=$AllClassicVM
            $AllClassicVM.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.ClassicEndpoints')
            #Create custom object for store data
            $AllVM = New-Object -TypeName PSCustomObject
            $AllVM | Add-Member -type NoteProperty -name Section -value $Section
            $AllVM | Add-Member -type NoteProperty -name Data -value $AllClassicVM
            #Add VM data to object
            if($AllClassicVM){
                $ReturnPluginObject | Add-Member -type NoteProperty -name ClassicEndpoints -value $AllVM
            }
        }
        else{
            Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzureADGeneralQueryEmptyMessage -f "Classic Endpoint", $AzureObject.TenantID) `
                                -Plugin $PluginName -Verbosity $Verbosity -IsWarning
        }
    }