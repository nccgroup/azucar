#Sample skeleton PowerShell plugin code
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
        #Do things here
		$ReturnValue = [PSCustomObject]@{Name='myCustomType';Expression={"NCCGroup Labs"}}
		
    }
    End{
        if($ReturnValue){
            #Work with SyncHash
            $SyncServer.$($PluginName)=$ReturnValue
            $ReturnValue.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.myDecoratedObject')
            #Create custom object for store data
            $MyVar = New-Object -TypeName PSCustomObject
            $MyVar | Add-Member -type NoteProperty -name Section -value $Section
            $MyVar | Add-Member -type NoteProperty -name Data -value $ReturnValue
            #Add data to object
            if($MyVar){
                $ReturnPluginObject | Add-Member -type NoteProperty -name Example -value $MyVar
            }
        }
        else{
            Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzureADGeneralQueryEmptyMessage -f "My Super Plugin", $AzureObject.TenantID) `
                                -Plugin $PluginName -Verbosity $Verbosity -IsWarning
        }
    }