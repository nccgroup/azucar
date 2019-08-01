#Azure get all keyvaults in subscription
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
        #Get pluginname and section
        $PluginName = $AzureObject.PluginName
        $Section = $AzureObject.AzureSection
        #Get Keyvaults
        $KeyVaults = $AzureObject.AzureResources | Where-Object {$_.type -like 'Microsoft.KeyVault/*'}
        $all_key_vaults = @();
        $all_keys = @();
        $all_secrets = @();
    }
    Process{
        
        Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzucarADGeneralTaskMessage -f "Azure Keyvaults", $bgRunspaceID, $PluginName, $AzureObject.TenantID) `
                                -Plugin $PluginName -IsHost -Color Green
        #Retrieve instance
        $Instance = $AzureObject.Instance
        #Retrieve Azure Resource Management Auth
        $RMAuth = $AzureObject.AzureConnections.ResourceManager
        #Retrieve Azure Keyvault Auth
        $VaultAuth = $AzureObject.AzureConnections.AzureVault
        if($KeyVaults){
            foreach($keyvault in $KeyVaults){
                $URI = ("{0}{1}?api-version={2}" `
                        -f $Instance.ResourceManager,$keyvault.id,'2018-02-14')
                $my_key_vault = Get-AzSecRMObject -OwnQuery $URI -Manual -Authentication $RMAuth `
                                                  -Verbosity $Verbosity -WriteLog $WriteLog
                if($my_key_vault){
                    #KeyVault object
                    $new_key_vault_object = New-Object -TypeName PSCustomObject
                    $new_key_vault_object | Add-Member -type NoteProperty -name id -value $my_key_vault.id
                    $new_key_vault_object | Add-Member -type NoteProperty -name name -value $my_key_vault.name
                    $new_key_vault_object | Add-Member -type NoteProperty -name location -value $my_key_vault.location
                    $new_key_vault_object | Add-Member -type NoteProperty -name skufamily -value $my_key_vault.properties.sku.family
                    $new_key_vault_object | Add-Member -type NoteProperty -name skuname -value $my_key_vault.properties.sku.name
                    $new_key_vault_object | Add-Member -type NoteProperty -name tenantId -value $my_key_vault.properties.tenantId
                    $new_key_vault_object | Add-Member -type NoteProperty -name vaultUri -value $my_key_vault.properties.vaultUri
                    $new_key_vault_object | Add-Member -type NoteProperty -name provisioningState -value $my_key_vault.properties.provisioningState
                    $new_key_vault_object | Add-Member -type NoteProperty -name enabledForDeployment -value $my_key_vault.properties.enabledForDeployment
                    $new_key_vault_object | Add-Member -type NoteProperty -name enabledForDiskEncryption -value $my_key_vault.properties.enabledForDiskEncryption
                    $new_key_vault_object | Add-Member -type NoteProperty -name enabledForTemplateDeployment -value $my_key_vault.properties.enabledForTemplateDeployment
                    #Get Network properties
                    if(-NOT $my_key_vault.properties.networkAcls){
                        $new_key_vault_object | Add-Member -type NoteProperty -name allowAccessFromAllNetworks -value $true    
                    }
                    elseif ($my_key_vault.properties.networkAcls.bypass -eq "AzureServices" -AND $my_key_vault.properties.networkAcls.defaultAction -eq "Allow"){
                        $new_key_vault_object | Add-Member -type NoteProperty -name allowAccessFromAllNetworks -value $true    
                    }
                    else{
                        $new_key_vault_object | Add-Member -type NoteProperty -name allowAccessFromAllNetworks -value $false        
                    }
                    #Get Recoverable options
                    if(-NOT $my_key_vault.properties.enablePurgeProtection){
                        $new_key_vault_object | Add-Member -type NoteProperty -name enablePurgeProtection -value $false    
                    }
                    else{
                        $new_key_vault_object | Add-Member -type NoteProperty -name enablePurgeProtection -value $my_key_vault.properties.enablePurgeProtection
                    }
                    if(-NOT $my_key_vault.properties.enableSoftDelete){
                        $new_key_vault_object | Add-Member -type NoteProperty -name enableSoftDelete -value $false    
                    }
                    else{
                        $new_key_vault_object | Add-Member -type NoteProperty -name enableSoftDelete -value $my_key_vault.properties.enableSoftDelete
                    }
                    #Add keyvault to array
                    $all_key_vaults += $new_key_vault_object
                    #Get Keys within vault
                    $URI = ("{0}keys?api-version={1}" -f $my_key_vault.properties.vaultUri,'2016-10-01')
                    $_keys = Get-AzSecRMObject -OwnQuery $URI -Manual -Authentication $VaultAuth `
                                               -Verbosity $Verbosity -WriteLog $WriteLog
                    if($_keys){
                        foreach($_key in $_keys){
                            $new_key = New-Object -TypeName PSCustomObject
                            $new_key | Add-Member -type NoteProperty -name id -value $_key.kid
                            $new_key | Add-Member -type NoteProperty -name enabled -value $_key.attributes.enabled
                            $new_key | Add-Member -type NoteProperty -name created -value $_key.attributes.created
                            $new_key | Add-Member -type NoteProperty -name updated -value $_key.attributes.updated
                            $new_key | Add-Member -type NoteProperty -name recoveryLevel -value $_key.attributes.recoveryLevel
                            #Check if key expires
                            if($_key.attributes.exp){
                                $new_key | Add-Member -type NoteProperty -name expires -value $_key.attributes.exp
                            }
                            else{
                                $new_key | Add-Member -type NoteProperty -name expires -value $false
                            }
                            #Add object to arrah
                            $all_keys += $new_key
                        }
                    }
                    #Get secrets within vault
                    $URI = ("{0}secrets?api-version={1}" -f $my_key_vault.properties.vaultUri,'7.0')
                    $_secrets = Get-AzSecRMObject -OwnQuery $URI -Manual -Authentication $VaultAuth `
                                               -Verbosity $Verbosity -WriteLog $WriteLog
                    if($_secrets){
                        foreach($_secret in $_secrets){
                            $new_secret = New-Object -TypeName PSCustomObject
                            $new_secret | Add-Member -type NoteProperty -name id -value $_secret.id
                            $new_secret | Add-Member -type NoteProperty -name enabled -value $_secret.attributes.enabled
                            $new_secret | Add-Member -type NoteProperty -name created -value $_secret.attributes.created
                            $new_secret | Add-Member -type NoteProperty -name updated -value $_secret.attributes.updated
                            $new_secret | Add-Member -type NoteProperty -name recoveryLevel -value $_secret.attributes.recoveryLevel
                            #Check if key expires
                            if($_secret.attributes.exp){
                                $new_secret | Add-Member -type NoteProperty -name expires -value $_secret.attributes.exp
                            }
                            else{
                                $new_secret | Add-Member -type NoteProperty -name expires -value $false
                            }
                            #Add object to arrah
                            $all_secrets += $new_secret
                        }
                    }
                }
            }
        }
    }
    End{
        if($all_key_vaults){
            #Work with SyncHash
            $SyncServer.$($PluginName)=$all_key_vaults
            $all_key_vaults.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.key_vaults')
            #Create custom object for store data
            $subscription_keyvaults = New-Object -TypeName PSCustomObject
            $subscription_keyvaults | Add-Member -type NoteProperty -name Section -value $Section
            $subscription_keyvaults | Add-Member -type NoteProperty -name Data -value $all_key_vaults
            #Add data to object
            if($subscription_keyvaults){
                $ReturnPluginObject | Add-Member -type NoteProperty -name azure_key_vaults -value $subscription_keyvaults
            }
        }
        else{
            Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzureADGeneralQueryEmptyMessage -f "Azure key vaults", $AzureObject.TenantID) `
                                -Plugin $PluginName -Verbosity $Verbosity -IsWarning
        }
        if($all_keys){
            #Work with SyncHash
            $SyncServer.$($PluginName)=$all_keys
            $all_keys.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.key_vaults.keys')
            #Create custom object for store data
            $subscription_keys = New-Object -TypeName PSCustomObject
            $subscription_keys | Add-Member -type NoteProperty -name Section -value $Section
            $subscription_keys | Add-Member -type NoteProperty -name Data -value $all_keys
            #Add data to object
            if($subscription_keys){
                $ReturnPluginObject | Add-Member -type NoteProperty -name azure_key_vaults_keys -value $subscription_keys
            }
        }
        else{
            Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzureADGeneralQueryEmptyMessage -f "Azure key vaults: Keys", $AzureObject.TenantID) `
                                -Plugin $PluginName -Verbosity $Verbosity -IsWarning
        }
        if($all_secrets){
            #Work with SyncHash
            $SyncServer.$($PluginName)=$all_secrets
            $all_secrets.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.key_vaults.secrets')
            #Create custom object for store data
            $subscription_secrets = New-Object -TypeName PSCustomObject
            $subscription_secrets | Add-Member -type NoteProperty -name Section -value $Section
            $subscription_secrets | Add-Member -type NoteProperty -name Data -value $all_secrets
            #Add data to object
            if($subscription_secrets){
                $ReturnPluginObject | Add-Member -type NoteProperty -name azure_key_vaults_secrets -value $subscription_secrets
            }
        }
        else{
            Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzureADGeneralQueryEmptyMessage -f "Azure key vaults: Secrets", $AzureObject.TenantID) `
                                -Plugin $PluginName -Verbosity $Verbosity -IsWarning
        }
    }