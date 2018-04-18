#Plugin extract policies from Azure AD
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

            [Parameter(Mandatory=$false, HelpMessage="Save exception in log file")]
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
        $AADConfig = $AzureObject.AzureConfig.AzureActiveDirectory
        $Section = $AzureObject.AzureSection
        Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzucarADPoliciesTaskMessage -f $bgRunspaceID, $PluginName, $AzureObject.TenantID) `
                                -Plugin $PluginName -IsHost -Color Green
        #Retrieve instance
        $Instance = $AzureObject.Instance
        #Retrieve Azure Active Directory Auth
        $AADAuth = $AzureObject.AzureConnections.ActiveDirectory
        #Get users
        $AllPolicies = Get-AzSecAADObject -Instance $Instance -Authentication $AADAuth `
                                          -Objectype "policies" -APIVersion $AADConfig.APIVersion -Verbosity $Verbosity -WriteLog $WriteLog
    }
    End{
        if($AllPolicies){
            #Work with SyncHash
            $SyncServer.$($PluginName)=$AllPolicies
            $AllPolicies.PSObject.TypeNames.Insert(0,'AzureAAD.NCCGroup.Policies')
            #Create custom object for store data
            $AllAADPolicies = New-Object -TypeName PSCustomObject
            $AllAADPolicies | Add-Member -type NoteProperty -name Section -value $Section
            $AllAADPolicies | Add-Member -type NoteProperty -name Data -value $AllPolicies
            #Add Users data to object
            if($AllPolicies){
                $ReturnPluginObject | Add-Member -type NoteProperty -name DomainPolicies -value $AllPolicies
            }
        }
        else{
            Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzureADPoliciesQueryEmptyMessage -f $AzureObject.TenantID) `
                                -Plugin $PluginName -Verbosity $Verbosity -IsWarning
        }
    }