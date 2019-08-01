#Extract information about policies applied to subscription
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
        #Import Global vars
        $LogPath = $AzureObject.LogPath
        Set-Variable LogPath -Value $LogPath -Scope Global
    }
    Process{
        $PluginName = $AzureObject.PluginName
        $AADConfig = $AzureObject.AzureConfig.AzureActiveDirectory
        $Section = $AzureObject.AzureSection
        Write-AzucarMessage -WriteLog $WriteLog -Message `
                            ($message.AzucarADDomainTaskMessage -f $bgRunspaceID, $PluginName, $AzureObject.TenantID) `
                            -Plugin $PluginName -IsHost -Color Green
        #Retrieve instance
        $Instance = $AzureObject.Instance
        #Get Subscription ID
        $subscriptionID = $AzureObject.AzureConnections.SecurityPortal.SubscriptionId
        #Command
        $command_policy_properties = ("Policy/getPreventionPolicy?subscriptionIdOrMgName={0}&isMg=false" -f $subscriptionID)
        #Retrieve Azure Active Directory Auth
        $SecPortalAuth = $AzureObject.AzureConnections.SecurityPortal
        #Get subscription policies
        $azure_subscription_policies = Get-AzSecurityEndpointObject -Instance $Instance -Authentication $SecPortalAuth `
                                                                    -Query $command_policy_properties -Method GET `
                                                                    -WriteLog $WriteLog -Verbosity $Verbosity
        if($azure_subscription_policies -is [System.Object]){
            $azure_subscription_policies = $azure_subscription_policies.toggles.preventionPolicyToggles
        }
    }
    End{
        if($azure_subscription_policies -is [System.Object]){
            #Work with SyncHash
            $SyncServer.$($PluginName)=$azure_subscription_policies
            $azure_subscription_policies.PSObject.TypeNames.Insert(0,'AzureAADPortal.NCCGroup.subscription.policies')
            #Create custom object for store data
            $SubscriptionPolicies = New-Object -TypeName PSCustomObject
            $SubscriptionPolicies | Add-Member -type NoteProperty -name Section -value $Section
            $SubscriptionPolicies | Add-Member -type NoteProperty -name Data -value $azure_subscription_policies
            #Add subscription policies data to object
            if($SubscriptionPolicies){
                $ReturnPluginObject | Add-Member -type NoteProperty -name azure_subscription_policies -value $SubscriptionPolicies
            }
        }
        else{
            Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzureADGeneralQueryEmptyMessage -f "Azure Subscription policies", $AzureObject.TenantID) `
                                -Plugin $PluginName -Verbosity $Verbosity -IsWarning
        }
        
    }