#Azure get Auto Provisioning
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
        #Import Global vars
        $LogPath = $AzureObject.LogPath
        Set-Variable LogPath -Value $LogPath -Scope Global

        $Section = $AzureObject.AzureSection
    }
    Process{
        $PluginName = $AzureObject.PluginName
        $Section = $AzureObject.AzureSection
        Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzucarADGeneralTaskMessage -f "Azure Auto provisioning status", $bgRunspaceID, $PluginName, $AzureObject.TenantID) `
                                -Plugin $PluginName -IsHost -Color Green
        #Retrieve instance
        $Instance = $AzureObject.Instance
        #Retrieve Azure Resource Management Auth
        $RMAuth = $AzureObject.AzureConnections.ResourceManager
        #List Auto provisioning status
        $autoProvisioningStatus = Get-AzSecRMObject -Instance $Instance -Authentication $RMAuth `
                                                    -Provider "microsoft.Security" -Objectype "autoProvisioningSettings" `
                                                    -APIVersion "2017-08-01-preview" -Verbosity $Verbosity `
                                                    -WriteLog $WriteLog
        $default_provisioning_status = $autoProvisioningStatus | Where-Object {$_.name -eq 'default'} | Select-Object -ExpandProperty properties
        $provisioning_status = New-Object -TypeName PSCustomObject
        $provisioning_status | Add-Member -type NoteProperty -name Name -value 'default'
        $provisioning_status | Add-Member -type NoteProperty -name autoprovision -value $default_provisioning_status.autoProvision
    }
    End{
        if($provisioning_status){
            #Work with SyncHash
            $SyncServer.$($PluginName)=$provisioning_status
            $provisioning_status.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.autoprovisioning.status')
            #Create custom object for store data
            $MonitorAgentProvisioningStatus = New-Object -TypeName PSCustomObject
            $MonitorAgentProvisioningStatus | Add-Member -type NoteProperty -name Section -value $Section
            $MonitorAgentProvisioningStatus | Add-Member -type NoteProperty -name Data -value $provisioning_status
            #Add data to object
            if($MonitorAgentProvisioningStatus){
                $ReturnPluginObject | Add-Member -type NoteProperty -name azure_vm_provisioning_status -value $MonitorAgentProvisioningStatus
            }
        }
        else{
            Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzureADGeneralQueryEmptyMessage -f "Azure VM Provisioning Status", $AzureObject.TenantID) `
                                -Plugin $PluginName -Verbosity $Verbosity -IsWarning
        }
    }