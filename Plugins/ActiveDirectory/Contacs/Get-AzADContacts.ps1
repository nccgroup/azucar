#Plugin extract contacts from Azure AD
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
        Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzucarADContactTaskMessage -f $bgRunspaceID, $PluginName, $AzureObject.TenantID) `
                                -Plugin $PluginName -IsHost -Color Green
        #Retrieve instance
        $Instance = $AzureObject.Instance
        #Retrieve Azure Active Directory Auth
        $AADAuth = $AzureObject.AzureConnections.ActiveDirectory
        #Get contacts
        $AllContacts = Get-AzSecAADObject -Instance $Instance -Authentication $AADAuth `
                                          -Objectype "contacts" -APIVersion $AADConfig.APIVersion -Verbosity $Verbosity -WriteLog $WriteLog
        $TmpContacts = @()
        if ($AllContacts){
            Write-Verbose "The contact search return $($AllContacts.Count)" @Verbosity
            #Get Contact Manager
            foreach ($contact in $AllContacts){
                $Manager = Get-AzSecAADLinkedObject -Instance $Instance `
                            -Authentication $AADAuth -Objectype "contacts" `
                            -ObjectId $group.objectId -Relationship "manager" `
                            -ObjectDisplayName $group.displayName `
                            -APIVersion $AADConfig.APIVersion -Verbosity $Verbosity -WriteLog $WriteLog
                $contact | Add-Member -type NoteProperty -name Manager -Value $Manager
                $TmpContacts+= $contact
            }
        }
    }
    End{
        if ($TmpContacts){
            Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzureADContactsSearchReturn -f $TmpContacts.Count) `
                                -Plugin $PluginName -Verbosity $Verbosity
            $TmpContacts.PSObject.TypeNames.Insert(0,'AzureAAD.NCCGroup.Contacts')
            #Work with SyncHash
            $SyncServer.$($PluginName)=$TmpContacts
            #Create custom object for store data
            $AllDomainContacts = New-Object -TypeName PSCustomObject
            $AllDomainContacts | Add-Member -type NoteProperty -name Section -value $Section
            $AllDomainContacts | Add-Member -type NoteProperty -name Data -value $TmpContacts
            #Add Contacts data to object
            if($TmpContacts){
                $ReturnPluginObject | Add-Member -type NoteProperty -name DomainContacts -value $AllDomainContacts
            }
        }
        else{
            Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzureADContactsQueryEmptyMessage -f $AzureObject.TenantID) `
                                -Plugin $PluginName -Verbosity $Verbosity -IsWarning
        }
    }