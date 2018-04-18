#Plugin extract audit logs from Azure AD
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
        Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzucarADAuditTaskMessage -f $bgRunspaceID, $PluginName, $AzureObject.TenantID) `
                                -Plugin $PluginName -IsHost -Color Green
        #Retrieve instance
        $Instance = $AzureObject.Instance
        #Retrieve Azure Active Directory Auth
        $AADAuth = $AzureObject.AzureConnections.ActiveDirectory
        Try{
            $DaysAgo = "{0:s}" -f (get-date).AddDays($AADConfig.AuditLogDaysAgo) + "Z"
        }
        Catch{
            $DaysAgo = -15
        }
        $Query = '&$filter=activityDate gt {0}' -f $DaysAgo
        #Get Audit Logs from Azure AAD
        $AllEvents = Get-AzSecAADObject -Instance $Instance -Authentication $AADAuth `
                     -Objectype "activities/audit" -APIVersion "beta" -Query $Query -Verbosity $Verbosity -WriteLog $WriteLog

        $TmpEvents = @()
        if ($AllEvents){
            Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzureADAuditSearchReturn -f $AllEvents.Count) `
                                -Plugin $PluginName -Verbosity $Verbosity
            foreach ($entry in $AllEvents){
                $entry.actor = $entry.actor.userPrincipalName
                $entry | Add-Member -type NoteProperty -name targetResourceType -Value $entry.targets.targetResourceType
                $entry | Add-Member -type NoteProperty -name targetobjectId -Value $entry.targets.objectId
                $entry | Add-Member -type NoteProperty -name targetName -Value $entry.targets.name
                $entry | Add-Member -type NoteProperty -name targetResourceType -Value $entry.targets.targetResourceType
                $entry | Add-Member -type NoteProperty -name targetUserPrincipalName -Value $entry.targets.userPrincipalName
                $Changes = $entry.targets.modifiedProperties
                $entry | Add-Member -type NoteProperty -name ChangeAttribute -Value (@($Changes.name) -join ',')
                $entry | Add-Member -type NoteProperty -name OldValue -Value (@($Changes.oldvalue) -join ',')
                $entry | Add-Member -type NoteProperty -name NewValue -Value (@($Changes.newvalue) -join ',')
                $TmpEvents += $entry
            }
            
            #$AllEvents| ogv
        }
    }
    End{
        if($TmpEvents){
            #Work with SyncHash
            $SyncServer.$($PluginName)=$TmpEvents
            $TmpEvents = $TmpEvents | Select-Object $AADConfig.AuditLogFilter
            $TmpEvents.PSObject.TypeNames.Insert(0,'AzureAAD.NCCGroup.AuditLogs')
            #Create custom object for store data
            $AllDomainEvents = New-Object -TypeName PSCustomObject
            $AllDomainEvents | Add-Member -type NoteProperty -name Section -value $Section
            $AllDomainEvents | Add-Member -type NoteProperty -name Data -value $TmpEvents
            #Add Log events data to object
            if($TmpEvents){
                $ReturnPluginObject | Add-Member -type NoteProperty -name DomainEvents -value $AllDomainEvents
            }
        }
        else{
            Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzureADAuditQueryEmptyMessage -f $AzureObject.TenantID) `
                                -Plugin $PluginName -Verbosity $Verbosity -IsWarning
        }
    }