#Azure Bots
#https://docs.microsoft.com/en-us/azure/bot-service/dotnet/bot-builder-dotnet-security?view=azure-bot-service-3.0
#https://github.com/Azure/azure-rest-api-specs/blob/master/specification/botservice/resource-manager/Microsoft.BotService/preview/2017-12-01/botservice.json
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

        $Section = $AzureObject.AzureSection
    }
    Process{
        $PluginName = $AzureObject.PluginName
        $Section = $AzureObject.AzureSection
        $AzureBot = $AzureObject.AzureConfig.AzureBotServices
        Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzucarADGeneralTaskMessage -f "Azure Bot Services", $bgRunspaceID, $PluginName, $AzureObject.TenantID) `
                                -Plugin $PluginName -IsHost -Color Green
        #Retrieve instance
        $Instance = $AzureObject.Instance
        #Retrieve Azure Resource Management Auth
        $RMAuth = $AzureObject.AzureConnections.ResourceManager
        #List All Azure Bots
        $azureBots = Get-AzSecRMObject -Instance $Instance -Authentication $RMAuth `
                                -Provider $AzureBot.Provider -Objectype "botServices" `
                                -APIVersion $AzureBot.APIVersion -Verbosity $Verbosity -WriteLog $WriteLog
        
        #Create array
        $allAzureBots = @()
        foreach ($bot in $azureBots){
            if($bot.id){
                $Properties = $bot | Select @{Name='id';Expression={$bot.id}},`
                                      @{Name='name';Expression={$bot.name}},`
                                      @{Name='location';Expression={$bot.location}},`
                                      @{Name='kind';Expression={$bot.kind}},`
                                      @{Name='provisioningState';Expression={$bot.properties.provisioningState}},`
                                      @{Name='displayName';Expression={$bot.properties.displayName}},`
                                      @{Name='description';Expression={$bot.properties.description}},`
                                      #Not yet implemented by MS
                                      @{Name='endpoint';Expression={$bot.properties.endpoint}},`
                                      @{Name='endpointVersion';Expression={$bot.properties.endpointVersion}}
                                                                    
                #Decorate object
                $Properties.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.azureBots')
                $allAzureBots+=$Properties
           }               	
       }
    }
    End{
        if($allAzureBots){
            #Work with SyncHash
            $SyncServer.$($PluginName)=$allAzureBots
            $allAzureBots.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.azureBots')
            #Create custom object for store data
            $MyAzureBots = New-Object -TypeName PSCustomObject
            $MyAzureBots | Add-Member -type NoteProperty -name Section -value $Section
            $MyAzureBots | Add-Member -type NoteProperty -name Data -value $allAzureBots
            #Add data to object
            if($MyAzureBots){
                $ReturnPluginObject | Add-Member -type NoteProperty -name AzureBots -value $MyAzureBots
            }
        }
        else{
            Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzureADGeneralQueryEmptyMessage -f "Azure Bots", $AzureObject.TenantID) `
                                -Plugin $PluginName -Verbosity $Verbosity -IsWarning
        }
    }