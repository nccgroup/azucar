#Azure DocumentDB
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
        $AzureDocumentDB = $AzureObject.AzureConfig.AzureDocumentDB
        $Section = $AzureObject.AzureSection
        Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzucarADGeneralTaskMessage -f "Azure DocumentDB accounts", $bgRunspaceID, $PluginName, $AzureObject.TenantID) `
                                -Plugin $PluginName -IsHost -Color Green
        #Retrieve instance
        $Instance = $AzureObject.Instance
        #Retrieve Azure Resource Management Auth
        $RMAuth = $AzureObject.AzureConnections.ResourceManager
        #List All WebApps within Azure Tenant
        $documentDBAccounts = Get-AzSecRMObject -Instance $Instance -Authentication $RMAuth `
                                -Provider $AzureDocumentDB.Provider -Objectype "databaseAccounts" `
                                -APIVersion $AzureDocumentDB.APIVersion -Verbosity $Verbosity -WriteLog $WriteLog

	    #Create array
        $allDocumentDBAccounts = @()
        foreach ($account in $documentDBAccounts.value){
            $Properties = $account | Select @{Name='id';Expression={$account.id}},`
                                  @{Name='name';Expression={$account.name}},`
                                  @{Name='kind';Expression={$account.kind}},`
                                  @{Name='location';Expression={$account.location}},`
                                  @{Name='provisioningState';Expression={$account.properties.provisioningState}},`
                                  @{Name='enableAutomaticFailover';Expression={$account.properties.enableAutomaticFailover}},`
                                  @{Name='isVirtualNetworkFilterEnabled';Expression={$account.properties.isVirtualNetworkFilterEnabled}},`
                                  @{Name='databaseAccountOfferType';Expression={$account.properties.databaseAccountOfferType}},`
                                  @{Name='ipRangeFilter';Expression={(@($account.properties.ipRangeFilter) -join ',')}},`
                                  @{Name='virtualNetworkRules';Expression={(@($account.properties.virtualNetworkRules) -join ',')}}                                    
            if($Properties){
                #Decorate object
                $Properties.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.DocumentDBAccounts')
                $allDocumentDBAccounts+=$Properties
            }
        }
    }
    End{
        if($allDocumentDBAccounts){
            #Work with SyncHash
            $SyncServer.$($PluginName)=$allDocumentDBAccounts
            $allDocumentDBAccounts.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.DocumentDBAccounts')
            #Create custom object for store data
            $AzureDocumentDBAccounts = New-Object -TypeName PSCustomObject
            $AzureDocumentDBAccounts | Add-Member -type NoteProperty -name Section -value $Section
            $AzureDocumentDBAccounts | Add-Member -type NoteProperty -name Data -value $allDocumentDBAccounts
            #Add data to object
            if($AzureDocumentDBAccounts){
                $ReturnPluginObject | Add-Member -type NoteProperty -name azure_documentdb -value $AzureDocumentDBAccounts
            }
        }
        else{
            Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzureADGeneralQueryEmptyMessage -f "Azure DocumentDB Accounts", $AzureObject.TenantID) `
                                -Plugin $PluginName -Verbosity $Verbosity -IsWarning
        }
    }