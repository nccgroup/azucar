#Azure get Security Center Builtin
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
        #List Security Center Bulletin
        $security_center_builtin = Get-AzSecRMObject -Instance $Instance -Authentication $RMAuth `
                                                      -Provider "microsoft.Authorization" -Objectype "policyAssignments/SecurityCenterBuiltIn" `
                                                      -APIVersion "2019-01-01" -Verbosity $Verbosity `
                                                      -WriteLog $WriteLog
        $acs_entries = @()
        foreach ($acs_entry in $security_center_builtin.properties.parameters.psobject.Properties){
            $Unit_Policy = New-Object -TypeName PSCustomObject
            $Unit_Policy | Add-Member -type NoteProperty -name PolicyName -value $acs_entry.name.ToString()
            $Unit_Policy | Add-Member -type NoteProperty -name Status -value $acs_entry.value.value.ToString()
            $Unit_Policy.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.ACS_Policy')
            $acs_entries+=$Unit_Policy
        }
    }
    End{
        if($acs_entries){
            #Work with SyncHash
            $SyncServer.$($PluginName)=$acs_entries
            $acs_entries.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.securitycenter.acsbuiltin.parameters')
            #Create custom object for store data
            $acs_builtin_parameters = New-Object -TypeName PSCustomObject
            $acs_builtin_parameters | Add-Member -type NoteProperty -name Section -value $Section
            $acs_builtin_parameters | Add-Member -type NoteProperty -name Data -value $acs_entries
            #Add data to object
            if($acs_builtin_parameters){
                $ReturnPluginObject | Add-Member -type NoteProperty -name azure_acs_builtin_policies -value $acs_builtin_parameters
            }
        }
        else{
            Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzureADGeneralQueryEmptyMessage -f "Azure Security Center Builtin Parameters", $AzureObject.TenantID) `
                                -Plugin $PluginName -Verbosity $Verbosity -IsWarning
        }
    }