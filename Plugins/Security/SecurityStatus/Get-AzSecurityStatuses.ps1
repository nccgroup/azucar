#Plugin extract about Security Statuses from Azure
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
    }
    Process{
        $PluginName = $AzureObject.PluginName
        $AzureSecStatus = $AzureObject.AzureConfig.SecurityStatuses
        $Section = $AzureObject.AzureSection
        Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzucarADGeneralTaskMessage -f "Security Statuses", $bgRunspaceID, $PluginName, $AzureObject.TenantID) `
                                -Plugin $PluginName -IsHost -Color Green
        #Retrieve instance
        $Instance = $AzureObject.Instance
        #Retrieve Azure Resource Management Auth
        $RMAuth = $AzureObject.AzureConnections.ResourceManager
        #List all VMs
        $AllStatus = Get-AzSecRMObject -Instance $Instance -Authentication $RMAuth `
                                       -Provider $AzureSecStatus.Provider -Objectype "securityStatuses" `
                                       -APIVersion $AzureSecStatus.APIVersion -Verbosity $Verbosity -WriteLog $WriteLog
        
        
        #Get primary object
        $AllSecStatus = @()
        foreach($Status in $AllStatus){
            $Properties = $Status.properties | Select-Object name, type, securityState, resourceGroupName, virtualMachineName, vmIpAddress, accountName, vmAgent
            $Properties.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.SecurityState')
            $AllSecStatus+=$Properties               
        }
    }
    End{
        if($AllSecStatus){
            #Work with SyncHash
            $SyncServer.$($PluginName)=$AllSecStatus
            $AllSecStatus.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.SecurityState')
            #Create custom object for store data
            $SecurityStatus = New-Object -TypeName PSCustomObject
            $SecurityStatus | Add-Member -type NoteProperty -name Section -value $Section
            $SecurityStatus | Add-Member -type NoteProperty -name Data -value $AllSecStatus
            #Add VM data to object
            if($SecurityStatus){
                $ReturnPluginObject | Add-Member -type NoteProperty -name azure_security_status -value $SecurityStatus
            }
        }
        else{
            Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzureADGeneralQueryEmptyMessage -f "Security Statuses", $AzureObject.TenantID) `
                                -Plugin $PluginName -Verbosity $Verbosity -IsWarning
        }
    }