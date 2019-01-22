#Azure Security Contacts
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
        Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzucarADGeneralTaskMessage -f "Azure Security Contacts", $bgRunspaceID, $PluginName, $AzureObject.TenantID) `
                                -Plugin $PluginName -IsHost -Color Green
        #Retrieve instance
        $Instance = $AzureObject.Instance
        #Retrieve Azure Resource Management Auth
        $RMAuth = $AzureObject.AzureConnections.ResourceManager
        #List All Security Contacts
        $securityContacts = Get-AzSecRMObject -Instance $Instance -Authentication $RMAuth `
                                -Provider "microsoft.Security" -Objectype "securityContacts" `
                                -APIVersion "2017-08-01-preview" -Verbosity $Verbosity -WriteLog $WriteLog
        #Create array
        $allsecurityContacts = @()
        foreach ($account in $securityContacts){
            $Properties = $account | Select @{Name='id';Expression={$account.id}},`
                                  @{Name='name';Expression={$account.name}},`
                                  @{Name='email';Expression={$account.properties.email}},`
                                  @{Name='phone';Expression={$account.properties.phone}},`
                                  @{Name='alertNotifications';Expression={$account.properties.alertNotifications}},`
                                  @{Name='alertsToAdmins';Expression={$account.properties.alertsToAdmins}}
                                                                    
            #Decorate object
            $Properties.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.securityContacts')
            $allsecurityContacts+=$Properties               	
       }
    }
    End{
        if($allsecurityContacts){
            #Work with SyncHash
            $SyncServer.$($PluginName)=$allsecurityContacts
            $allsecurityContacts.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.securityContacts')
            #Create custom object for store data
            $AzureSecurityContacts = New-Object -TypeName PSCustomObject
            $AzureSecurityContacts | Add-Member -type NoteProperty -name Section -value $Section
            $AzureSecurityContacts | Add-Member -type NoteProperty -name Data -value $allsecurityContacts
            #Add data to object
            if($AzureSecurityContacts){
                $ReturnPluginObject | Add-Member -type NoteProperty -name SecurityContacts -value $AzureSecurityContacts
            }
        }
        else{
            Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzureADGeneralQueryEmptyMessage -f "Azure Security Contacts", $AzureObject.TenantID) `
                                -Plugin $PluginName -Verbosity $Verbosity -IsWarning
        }
    }