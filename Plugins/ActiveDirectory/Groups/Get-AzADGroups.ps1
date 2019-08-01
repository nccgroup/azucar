#Plugin extract users from AD
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
        Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzucarADGroupsTaskMessage -f $bgRunspaceID, $PluginName, $AzureObject.TenantID) `
                                -Plugin $PluginName -IsHost -Color Green
        #Retrieve instance
        $Instance = $AzureObject.Instance
        #Retrieve Azure Active Directory Auth
        $AADAuth = $AzureObject.AzureConnections.ActiveDirectory
        #Get groups
        $AllGroups = Get-AzSecAADObject -Instance $Instance -Authentication $AADAuth `
                                        -Objectype "groups" -APIVersion $AADConfig.APIVersion -Verbosity $Verbosity -WriteLog $WriteLog
        $TmpGroups = @()
        if ($AllGroups){
            Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzureADGroupSearchReturn -f $AllGroups.Count) `
                                -Plugin $PluginName -Verbosity $Verbosity
            foreach ($group in $AllGroups){
                $GroupCount = Get-AzSecAADLinkedObject -Instance $Instance `
                            -Authentication $AADAuth -Objectype "groups" `
                            -ObjectId $group.objectId -Relationship "members" `
                            -ObjectDisplayName $group.displayName `
                            -APIVersion $AADConfig.APIVersion `
                            -GetLinks -Verbosity $Verbosity -WriteLog $WriteLog
                
                $group | Add-Member -type NoteProperty -name Members -Value $GroupCount.Count
                $TmpGroups+=$group
            }
        }
    }
    End{
        if($TmpGroups){
            #Work with SyncHash
            $SyncServer.$($PluginName)=$TmpGroups
            $TmpGroups = $TmpGroups | Select-Object $AADConfig.GroupFilter
            $TmpGroups.PSObject.TypeNames.Insert(0,'AzureAAD.NCCGroup.Groups')
            #Create custom object for store data
            $AllDomainGroups = New-Object -TypeName PSCustomObject
            $AllDomainGroups | Add-Member -type NoteProperty -name Section -value $Section
            $AllDomainGroups | Add-Member -type NoteProperty -name Data -value $TmpGroups
            #Add Groups data to object
            if($TmpGroups){
                $ReturnPluginObject | Add-Member -type NoteProperty -name azure_domain_groups -value $AllDomainGroups
            }
        }
        else{
            Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzureADGroupsQueryEmptyMessage -f $AzureObject.TenantID) `
                                -Plugin $PluginName -Verbosity $Verbosity -IsWarning
        }
    }