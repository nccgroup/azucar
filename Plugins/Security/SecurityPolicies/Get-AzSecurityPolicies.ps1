#Plugin extract about Security Policies from Azure
#https://msdn.microsoft.com/en-us/library/azure/mt704061.aspx
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
        $AzureSecPolicies = $AzureObject.AzureConfig.SecurityPolicies
        $Section = $AzureObject.AzureSection
        Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzucarADGeneralTaskMessage -f "Security Policies", $bgRunspaceID, $PluginName, $AzureObject.TenantID) `
                                -Plugin $PluginName -IsHost -Color Green
        #Retrieve instance
        $Instance = $AzureObject.Instance
        #Retrieve Azure Resource Management Auth
        $RMAuth = $AzureObject.AzureConnections.ResourceManager
        #List All Security Policies
        $SecPolicies = Get-AzSecRMObject -Instance $Instance -Authentication $RMAuth `
                                         -Provider $AzureSecPolicies.Provider -Objectype "policies" `
                                         -APIVersion $AzureSecPolicies.APIVersion -Verbosity $Verbosity -WriteLog $WriteLog
        
        #Get primary object
        $AllSecPolicies = @()
        if($SecPolicies){
            foreach($Policy in $SecPolicies){
                $Properties = $Policy.properties | Select-Object name, policyLevel, unique, logCollection, `
                                                   @{Name='Security Contacts Emails';Expression={@($_.securityContactConfiguration.securityContactEmails) -join ','}},
                                                   @{Name='Security Contacts Phone';Expression={$_.securityContactConfiguration.securityContactPhone}},
                                                   @{Name='Last Saved Policy';Expression={$_.securityContactConfiguration.lastSaveDateTime}},
                                                   @{Name='Enabled Notifications';Expression={$_.securityContactConfiguration.areNotificationsOn}},
                                                   @{Name='Send emails to Subscription Owner';Expression={$_.securityContactConfiguration.sendToAdminOn}},
                                                   @{Name='Recommendation Patch';Expression={$_.recommendations.patch}},
                                                   @{Name='Recommendation Baseline';Expression={$_.recommendations.baseline}},
                                                   @{Name='Recommendation AntiMalware';Expression={$_.recommendations.antimalware}},
                                                   @{Name='Recommendation Disk Encryption';Expression={$_.recommendations.diskEncryption}},
                                                   @{Name='Recommendation Access Control List';Expression={$_.recommendations.acls}},
                                                   @{Name='Recommendation Network Security Groups';Expression={$_.recommendations.nsgs}},
                                                   @{Name='Recommendation WAF';Expression={$_.recommendations.waf}},
                                                   @{Name='Recommendation SQL Audit';Expression={$_.recommendations.sqlAuditing}},
                                                   @{Name='Recommendation SQL TDE';Expression={$_.recommendations.sqlTde}},
                                                   @{Name='Recommendation Next Generation Firewall';Expression={$_.recommendations.ngfw}},
                                                   @{Name='Recommendation Vulnerability Assessment';Expression={$_.recommendations.vulnerabilityAssessment}},
                                                   @{Name='Recommendation Storage Encryption';Expression={$_.recommendations.storageEncryption}},
                                                   @{Name='Recommendation Just-In-Time Network Access';Expression={$_.recommendations.jitnetworkAccess}} 
                #Decorate Object
                $Properties.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.SecurityPolicies')
                $AllSecPolicies+=$Properties               
            }
        }
    }
    End{
        if($AllSecPolicies){
            #Work with SyncHash
            $SyncServer.$($PluginName)=$AllSecPolicies
            $AllSecPolicies.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.SecurityPolicies')
            #Create custom object for store data
            $SecurityPolicy = New-Object -TypeName PSCustomObject
            $SecurityPolicy | Add-Member -type NoteProperty -name Section -value $Section
            $SecurityPolicy | Add-Member -type NoteProperty -name Data -value $AllSecPolicies
            #Add VM data to object
            if($SecurityPolicy){
                $ReturnPluginObject | Add-Member -type NoteProperty -name azure_security_policies -value $SecurityPolicy
            }
        }
        else{
            Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzureADGeneralQueryEmptyMessage -f "Security Policies", $AzureObject.TenantID) `
                                    -Plugin $PluginName -Verbosity $Verbosity -IsWarning
        }
    }