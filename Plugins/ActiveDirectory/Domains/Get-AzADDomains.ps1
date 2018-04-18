#Plugin extract information about domain from Azure AD
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
        Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzucarADDomainTaskMessage -f $bgRunspaceID, $PluginName, $AzureObject.TenantID) `
                                -Plugin $PluginName -IsHost -Color Green
        #Retrieve instance
        $Instance = $AzureObject.Instance
        #Retrieve Azure Active Directory Auth
        $AADAuth = $AzureObject.AzureConnections.ActiveDirectory
        #Get users
        $AllDomains = Get-AzSecAADObject -Instance $Instance -Authentication $AADAuth `
                                         -Objectype "domains" -APIVersion $AADConfig.APIVersion -Verbosity $Verbosity -WriteLog $WriteLog
        $tmpDomains = @()
        if ($AllDomains){
            Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzureADDomainSearchReturn -f $AllDomains.Count) `
                                -Plugin $PluginName -Verbosity $Verbosity
            foreach ($domain in $AllDomains){
                $domain.supportedServices = (@($domain.supportedServices) -join ',')
                $tmpDomains+=$domain
            }
        }
    }
    End{
        if($tmpDomains){
            #Work with SyncHash
            $SyncServer.$($PluginName)=$tmpDomains
            $TmpGroups.PSObject.TypeNames.Insert(0,'AzureAAD.NCCGroup.Domains')
            #Create custom object for store data
            $AllDomainInfo = New-Object -TypeName PSCustomObject
            $AllDomainInfo | Add-Member -type NoteProperty -name Section -value $Section
            $AllDomainInfo | Add-Member -type NoteProperty -name Data -value $tmpDomains
            #Add Users data to object
            if($tmpDomains){
                $ReturnPluginObject | Add-Member -type NoteProperty -name DomainInfo -value $AllDomainInfo
            }
        }
        else{
            Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzureADDomainQueryEmptyMessage -f $AzureObject.TenantID) `
                                -Plugin $PluginName -Verbosity $Verbosity -IsWarning
        }
        
    }