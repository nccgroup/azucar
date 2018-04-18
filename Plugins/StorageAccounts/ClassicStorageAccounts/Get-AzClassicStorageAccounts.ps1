#Plugin extract Classic Storage Account information from Azure
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

        #Convert Label
        Function _ConvertLabel{
             Param (
                [parameter(Mandatory=$false, HelpMessage="String Object")]
                [String]$Object

            )
            Begin{
                #Convert from Base64
                $ASCII = [convert]::FromBase64String($Object)
            }
            Process{
                if($ASCII){
                    $word = $ASCII | %{[char]$_}
                    $Word = $Word -join ''
                }
            }
            End{
                if($word){
                    return $word
                }
            }
        }
    }
    Process{
        $PluginName = $AzureObject.PluginName
        $Section = $AzureObject.AzureSection
        Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzucarADGeneralTaskMessage -f "Classic Storage Accounts", $bgRunspaceID, $PluginName, $AzureObject.TenantID) `
                            -Plugin $PluginName -IsHost -Color Green
        #Retrieve instance
        $Instance = $AzureObject.Instance
        #Retrieve Azure Service Management Auth
        $SMAuth = $AzureObject.AzureConnections.ServiceManagement
        #List All Classic Storage Accounts
        [xml]$StorageAccounts= Get-AzSecSMObject -Instance $Instance -Authentication $SMAuth -ObjectType "storageservices" -Verbosity $Verbosity -WriteLog $WriteLog
        #Get primary object
        $AllStorageAccounts = @()
        if ($StorageAccounts){
            foreach($Account in $StorageAccounts.StorageServices.StorageService){
                $StrAccount = New-Object -TypeName PSCustomObject
                $StrAccount | Add-Member -type NoteProperty -name name -value $Account.ServiceName
                $StrAccount | Add-Member -type NoteProperty -name location -value $Account.StorageServiceProperties.Location
                $StrAccount | Add-Member -type NoteProperty -name CreationTime -value $Account.StorageServiceProperties.CreationTime
                $StrAccount | Add-Member -type NoteProperty -name label -value ( _ConvertLabel -Object $Account.StorageServiceProperties.Label)
                $StrAccount | Add-Member -type NoteProperty -name status -value $Account.StorageServiceProperties.Status
                $StrAccount | Add-Member -type NoteProperty -name GeoPrimaryRegion -value $Account.StorageServiceProperties.GeoPrimaryRegion
                $StrAccount | Add-Member -type NoteProperty -name StatusOfPrimary -value $Account.StorageServiceProperties.StatusOfPrimary
                $StrAccount | Add-Member -type NoteProperty -name GeoSecondaryRegion -value $Account.StorageServiceProperties.GeoSecondaryRegion
                $StrAccount | Add-Member -type NoteProperty -name StatusOfSecondary -value $Account.StorageServiceProperties.StatusOfSecondary
                $StrAccount | Add-Member -type NoteProperty -name AccountType -value $Account.StorageServiceProperties.AccountType
                #Search for Extended Properties
                foreach($Extended in $Account.ExtendedProperties.ExtendedProperty){
                    if ($Extended.Name -eq 'ResourceGroup'){
                        $StrAccount | Add-Member -type NoteProperty -name ResourceGroup -value $Extended.Value
                    }
                    elseif ($Extended.Name -eq 'ResourceLocation'){
                        $StrAccount | Add-Member -type NoteProperty -name ResourceLocation -value $Extended.Value
                    }
                }
                #Decore Object
                $StrAccount.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.ClassicStorageAccount')
                #Add to Object
                $AllStorageAccounts+=$StrAccount
            }
        }
    }
    End{
        if($AllStorageAccounts){
            #Work with SyncHash
            $SyncServer.$($PluginName)=$AllStorageAccounts
            $AllStorageAccounts.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.ClassicStorageAccounts')
            #Create custom object for store data
            $AllAccounts = New-Object -TypeName PSCustomObject
            $AllAccounts | Add-Member -type NoteProperty -name Section -value $Section
            $AllAccounts | Add-Member -type NoteProperty -name Data -value $AllStorageAccounts
            #Add data to object
            if($AllAccounts){
                $ReturnPluginObject | Add-Member -type NoteProperty -name ClassicStorageAccounts -value $AllAccounts
            }
        }
        else{
            Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzureADGeneralQueryEmptyMessage -f "Classic Storage Accounts", $AzureObject.TenantID) `
                                -Plugin $PluginName -Verbosity $Verbosity -IsWarning
        }
    }