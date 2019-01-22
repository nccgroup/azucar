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
        #List All NSGs
        $StorageAccounts= Get-AzSecRMObject -Instance $Instance -Authentication $RMAuth `
                                            -Provider $AzureStorageAccountConfig.Provider -Objectype "storageAccounts" `
                                            -APIVersion $AzureStorageAccountConfig.APIVersion -Verbosity $Verbosity -WriteLog $WriteLog
        
        #Get primary object
        $AllStorageAccounts = @()
        foreach($StorageAccount in $StorageAccounts){
            #Getting information about Storage Account
            Write-AzucarMessage -WriteLog $WriteLog -Message ("Found storage account in {0}..." -f $StorageAccount.location) `
                                -Plugin $PluginName -Verbosity $Verbosity -IsVerbose
            
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
                #Get Encryption Status
                if($properties.encryption){
                    $StrAccount | Add-Member -type NoteProperty -name isEncrypted -value $true
                    $StrAccount | Add-Member -type NoteProperty -name lastEnabledTime -value $properties.encryption.services.blob.lastEnabledTime
                }
                else{
                    $StrAccount | Add-Member -type NoteProperty -name isEncrypted -value $false
                    $StrAccount | Add-Member -type NoteProperty -name lastEnabledTime -value $false
                }     
            }
            #Decore Object
            $StrAccount.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.StorageAccount')
            #Add to Object
            $AllStorageAccounts+=$StrAccount
        }
    }
    End{
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
                $ReturnPluginObject | Add-Member -type NoteProperty -name StorageAccounts -value $AllAccounts
            }
        }
        else{
            Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzureADGeneralQueryEmptyMessage -f "Storage Accounts", $AzureObject.TenantID) `
                                -Plugin $PluginName -Verbosity $Verbosity -IsWarning
        }
    }