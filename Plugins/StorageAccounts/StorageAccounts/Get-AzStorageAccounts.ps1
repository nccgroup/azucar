#Plugin extract Storage Account information from Azure
#https://docs.microsoft.com/en-us/azure/azure-policy/scripts/ensure-https-stor-acct
#https://docs.microsoft.com/en-us/azure/azure-policy/scripts/ensure-store-file-enc
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
        $AzureStorageAccountConfig = $AzureObject.AzureConfig.StorageAccounts
        $Section = $AzureObject.AzureSection
        Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzucarADGeneralTaskMessage -f "Storage Accounts", $bgRunspaceID, $PluginName, $AzureObject.TenantID) `
                                -Plugin $PluginName -IsHost -Color Green
        #Retrieve instance
        $Instance = $AzureObject.Instance
        #Retrieve Azure Resource Management Auth
        $RMAuth = $AzureObject.AzureConnections.ResourceManager
        $StorageAuth = $AzureObject.AzureConnections.AzureStorage
        #Get all alerts 
        $current_date = [datetime]::Now.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        $90_days = [datetime]::Now.AddDays(-90).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        $tmp_filter = ("eventTimestamp ge \'{0}\' and eventTimestamp le \'{1}\'" -f $90_days, $current_date)
        $filter = [System.Text.RegularExpressions.Regex]::Unescape($tmp_filter)
        $URI = ('{0}{1}/providers/microsoft.insights/eventtypes/management/values?api-Version={2}&$filter={3}' `
                -f $Instance.ResourceManager,$AzureObject.Subscription.id,'2017-03-01-preview', $filter)
        $all_alerts = Get-AzSecRMObject -OwnQuery $URI -Manual -Authentication $RMAuth `
                                                -Verbosity $Verbosity -WriteLog $WriteLog
        #List All NSGs
        $StorageAccounts= Get-AzSecRMObject -Instance $Instance -Authentication $RMAuth `
                                            -Provider $AzureStorageAccountConfig.Provider -Objectype "storageAccounts" `
                                            -APIVersion $AzureStorageAccountConfig.APIVersion -Verbosity $Verbosity -WriteLog $WriteLog
        
        #Get primary object
        $AllStorageAccounts = @()
        $AllStorageAccountsPublicBlobs= @()
        foreach($StorageAccount in $StorageAccounts){
            #Getting information about Storage Account
            Write-AzucarMessage -WriteLog $WriteLog -Message ("Found storage account in {0}..." -f $StorageAccount.location) `
                                -Plugin $PluginName -Verbosity $Verbosity -IsVerbose

            #Get Key rotation info
            $last_rotation_dates = $all_alerts | Where-Object {$_.resourceId -eq $StorageAccount.id -and $_.authorization.action -eq "Microsoft.Storage/storageAccounts/regenerateKey/action" -and $_.status.localizedValue -eq "Succeeded"} | Select-Object -ExpandProperty eventTimestamp
            $last_rotated_date = $last_rotation_dates | Select-Object -First 1
            
            foreach ($properties in $StorageAccount.properties){
                $StrAccount = New-Object -TypeName PSCustomObject
                $StrAccount | Add-Member -type NoteProperty -name name -value $StorageAccount.name
                $StrAccount | Add-Member -type NoteProperty -name location -value $StorageAccount.location
                $StrAccount | Add-Member -type NoteProperty -name ResourceGroupName -value $StorageAccount.id.Split("/")[4]
                $StrAccount | Add-Member -type NoteProperty -name Kind -value $StorageAccount.kind
                $StrAccount | Add-Member -type NoteProperty -name SkuName -value $StorageAccount.sku.name
                $StrAccount | Add-Member -type NoteProperty -name SkuTier -value $StorageAccount.sku.tier
                $StrAccount | Add-Member -type NoteProperty -name CreationTime -value $properties.creationTime
                $StrAccount | Add-Member -type NoteProperty -name primaryLocation -value $properties.primaryLocation
                $StrAccount | Add-Member -type NoteProperty -name statusofPrimary -value $properties.statusOfPrimary
                $StrAccount | Add-Member -type NoteProperty -name SkuName -value $StorageAccount.sku.name
                $StrAccount | Add-Member -type NoteProperty -name supportsHttpsTrafficOnly -value $properties.supportsHttpsTrafficOnly
                #Translate Key rotation info
                if($last_rotation_dates.count -ge 2){
                    $StrAccount | Add-Member -type NoteProperty -name isKeyRotated -value $true
                    $StrAccount | Add-Member -type NoteProperty -name lastRotatedKeys -value $last_rotated_date
                }
                else{
                    $StrAccount | Add-Member -type NoteProperty -name isKeyRotated -value $false
                    $StrAccount | Add-Member -type NoteProperty -name lastRotatedKeys -value $null
                }
                #Search for public blobs
                $blob_container_uri = ("https://{0}.blob.core.windows.net?restype=container&comp=list" -f $StorageAccount.name)
                [xml]$blobs = Get-AzSecurityEndpointObject -OwnQuery $blob_container_uri -Authentication $StorageAuth -Verbosity $Verbosity -WriteLog $WriteLog
                $public_blobs = $blobs.EnumerationResults.Containers.Container | Where-Object {$_.Properties.PublicAccess}
                if($public_blobs){
                    foreach($public_container in $public_blobs){
                        $container = New-Object -TypeName PSCustomObject
                        $container | Add-Member -type NoteProperty -name storageaccountname -value $StorageAccount.name
                        $container | Add-Member -type NoteProperty -name blobname -value $public_container.name
                        $container | Add-Member -type NoteProperty -name publicaccess -value $public_container.properties.publicaccess
                        #Add to array
                        $AllStorageAccountsPublicBlobs+=$container
                    }
                }
                #Get Encryption Status
                if($properties.encryption.services.blob){
                    $StrAccount | Add-Member -type NoteProperty -name isBlobEncrypted -value $properties.encryption.services.blob.enabled
                    $StrAccount | Add-Member -type NoteProperty -name lastBlobEncryptionEnabledTime -value $properties.encryption.services.blob.lastEnabledTime
                }
                if($properties.encryption.services.file){
                    $StrAccount | Add-Member -type NoteProperty -name isFileEncrypted -value $properties.encryption.services.file.enabled
                    $StrAccount | Add-Member -type NoteProperty -name lastFileEnabledTime -value $properties.encryption.services.file.lastEnabledTime
                }
                else{
                    $StrAccount | Add-Member -type NoteProperty -name isEncrypted -value $false
                    $StrAccount | Add-Member -type NoteProperty -name lastEnabledTime -value $false
                }
                #Get Network Configuration Status     
                if($properties.networkAcls){
                    $fwconf = $properties.networkAcls
                    if($fwconf.bypass -eq 'AzureServices'){
                        $StrAccount | Add-Member -type NoteProperty -name AllowAzureServices -value $true
                    }
                    else{
                        $StrAccount | Add-Member -type NoteProperty -name AllowAzureServices -value $false
                    }
                    if(-NOT $fwconf.virtualNetworkRules -AND -NOT $fwconf.ipRules -AND $fwconf.defaultAction -eq 'Allow'){
                        $StrAccount | Add-Member -type NoteProperty -name AllowAccessFromAllNetworks -value $true
                    }
                    else{
                        $StrAccount | Add-Member -type NoteProperty -name AllowAccessFromAllNetworks -value $false
                    }
                }
                #Get ATP for Storage Account
                $uri = ("{0}{1}/{2}?api-version={3}" -f $Instance.ResourceManager, $StorageAccount.id, "providers/Microsoft.Security/advancedThreatProtectionSettings/current", "2017-08-01-preview")
                $StrAccountATPInfo = Get-AzSecRMObject -OwnQuery $uri -Manual -Authentication $RMAuth -Verbosity $Verbosity -WriteLog $WriteLog
                if($StrAccountATPInfo){
                    $StrAccount | Add-Member -type NoteProperty -name AdvancedProtectionEnabled -value $StrAccountATPInfo.properties.isEnabled
                }
            }
            #Decore Object
            $StrAccount.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.StorageAccount')
            #Add to Object
            $AllStorageAccounts+=$StrAccount
        }
    }
    End{
        if($AllStorageAccounts -or $AllStorageAccountsPublicBlobs){
            if($AllStorageAccounts){
                #Work with SyncHash
                $SyncServer.$($PluginName)=$AllStorageAccounts
                $AllStorageAccounts.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.StorageAccounts')
                #Create custom object for store data
                $AllAccounts = New-Object -TypeName PSCustomObject
                $AllAccounts | Add-Member -type NoteProperty -name Section -value $Section
                $AllAccounts | Add-Member -type NoteProperty -name Data -value $AllStorageAccounts
                #Add data to object
                if($AllAccounts){
                    $ReturnPluginObject | Add-Member -type NoteProperty -name azure_storage_accounts -value $AllAccounts
                }
            }
            if($AllStorageAccountsPublicBlobs){
                #Add public blobs
                #Work with SyncHash
                $SyncServer.$($PluginName)=$AllStorageAccountsPublicBlobs
                $AllStorageAccountsPublicBlobs.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.StorageAccounts.PublicBlobs')
                #Create custom object for store data
                $AllPublicBlobs = New-Object -TypeName PSCustomObject
                $AllPublicBlobs | Add-Member -type NoteProperty -name Section -value $Section
                $AllPublicBlobs | Add-Member -type NoteProperty -name Data -value $AllStorageAccountsPublicBlobs
                #Add data to object
                if($AllPublicBlobs){
                    $ReturnPluginObject | Add-Member -type NoteProperty -name azure_storage_public_blobs -value $AllPublicBlobs
                }
            }
        }
        else{
            Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzureADGeneralQueryEmptyMessage -f "Storage Accounts", $AzureObject.TenantID) `
                                -Plugin $PluginName -Verbosity $Verbosity -IsWarning
        }
    }