#Plugin extract about WAF from Azure
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
        $AzureWAFConfig = $AzureObject.AzureConfig.WebApplicationFirewall
        $Section = $AzureObject.AzureSection
        Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzucarADGeneralTaskMessage -f "Web Application Firewall", $bgRunspaceID, $PluginName, $AzureObject.TenantID) `
                            -Plugin $PluginName -IsHost -Color Green
        
        Write-AzucarMessage -WriteLog $WriteLog -Message ("Searching for Web Application Gateways in {0}..." -f $AzureObject.Instance.ResourceManager) `
                            -Plugin $PluginName -Verbosity $Verbosity -IsVerbose

        #Retrieve instance
        $Instance = $AzureObject.Instance
        #Retrieve Azure Resource Manager Auth
        $RMAuth = $AzureObject.AzureConnections.ResourceManager
        $ResourceGroups = $AzureObject.ResourceGroups
        #Creating Arrays
        $AllWAFInfo = @()
        $AllWAFs = @()
        #Get All WAF within Resource Group
        foreach ($RMGroup in $ResourceGroups){
            $NewWAF = Get-AzSecRMObject -Instance $Instance -Authentication $RMAuth `
                                        -Provider $AzureWAFConfig.Provider -ResourceGroup $RMGroup.name `
                                        -Objectype "applicationGateways" -APIVersion $AzureWAFConfig.APIVersion `
                                        -Verbosity $Verbosity -WriteLog $WriteLog
            $AllWAFs += $NewWAF
        }        
        foreach($WAF in $AllWAFs){
            $WAF = $WAF.value
            if($WAF){
                Write-AzucarMessage -WriteLog $WriteLog -Message ("Getting information for {0} Web Application Firewall..." -f $WAF.name) `
                                    -Plugin $PluginName -Verbosity $Verbosity -IsVerbose
            
                Write-AzucarMessage -WriteLog $WriteLog -Message ("Getting health status for {0} Web Application Firewall..." -f $WAF.name) `
                                    -Plugin $PluginName -Verbosity $Verbosity -IsVerbose

            
                $uri = ("{0}{1}/{2}?api-version={3}" -f $Instance.ResourceManager, ($WAF.id).subString(1), 'backendhealth', $AzureWAFConfig.APIVersion)
                #Create Object
                $MyWAF = New-Object -TypeName PSCustomObject
                $MyWAF | Add-Member -type NoteProperty -name WafName -value $WAF.name
                $MyWAF | Add-Member -type NoteProperty -name WafETag -value $WAF.location
                $MyWAF | Add-Member -type NoteProperty -name WafLocation -value $WAF.etag
                $MyWAF | Add-Member -type NoteProperty -name WafProvisionState -value $WAF.properties.provisioningState
                $MyWAF | Add-Member -type NoteProperty -name WafResourceGuid -value $WAF.properties.resourceGuid
                $MyWAF | Add-Member -type NoteProperty -name WafOperationalState -value $WAF.properties.operationalState
                $MyWAF | Add-Member -type NoteProperty -name WafConfigurationSKU -value $WAF.properties.sku.name
                $MyWAF | Add-Member -type NoteProperty -name WafConfigurationSKUTier -value $WAF.properties.sku.tier
                $MyWAF | Add-Member -type NoteProperty -name WafConfigurationSKUCapacity -value $WAF.properties.sku.capacity
                $MyWAF | Add-Member -type NoteProperty -name WafWebApplicationFirewallEnabled -value $WAF.properties.webApplicationFirewallConfiguration.enabled
                $MyWAF | Add-Member -type NoteProperty -name WafWebApplicationFirewallMode -value $WAF.properties.webApplicationFirewallConfiguration.firewallMode
                $MyWAF | Add-Member -type NoteProperty -name WafWebApplicationFirewallRuleSet -value $WAF.properties.webApplicationFirewallConfiguration.ruleSetType
                $MyWAF | Add-Member -type NoteProperty -name WafWebApplicationFirewallRuleSetVersion -value $WAF.properties.webApplicationFirewallConfiguration.ruleSetVersion
                $MyWAF | Add-Member -type NoteProperty -name WafWebApplicationFirewallDisabledRuleGroups -value (@($WAF.properties.webApplicationFirewallConfiguration.disabledRuleGroups) -join ',')
                #Add to array
                $AllWAFInfo +=$MyWAF
            }
        }
    }
    End{
        if($AllWAFInfo){
            #Work with SyncHash
            $SyncServer.$($PluginName)=$AllWAFInfo
            $AllWAFInfo.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.WebApplicationFirewall')
            #Create custom object for store data
            $AllWAF = New-Object -TypeName PSCustomObject
            $AllWAF | Add-Member -type NoteProperty -name Section -value $Section
            $AllWAF | Add-Member -type NoteProperty -name Data -value $AllWAFInfo
            #Add WAF data to object
            if($AllWAF){
                $ReturnPluginObject | Add-Member -type NoteProperty -name azure_web_application_firewall -value $AllWAF
            }
        }
        else{
            Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzureADGeneralQueryEmptyMessage -f "Web Application Firewall", $AzureObject.TenantID) `
                                -Plugin $PluginName -Verbosity $Verbosity -IsWarning
        }
    }