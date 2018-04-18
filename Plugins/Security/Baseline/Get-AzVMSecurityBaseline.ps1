#Plugin extract about Security Baseline from Azure
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
        $AzureSecStatus = $AzureObject.AzureConfig.SecurityStatuses
        $Section = $AzureObject.AzureSection
        Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzucarADGeneralTaskMessage -f "Security Baseline", $bgRunspaceID, $PluginName, $AzureObject.TenantID) `
                                -Plugin $PluginName -IsHost -Color Green
        #Retrieve instance
        $Instance = $AzureObject.Instance
        #Retrieve Azure Resource Management Auth
        $RMAuth = $AzureObject.AzureConnections.ResourceManager
        #List all VMs
        $AllStatus = Get-AzSecRMObject -Instance $Instance -Authentication $RMAuth `
                                       -Provider $AzureSecStatus.Provider -Objectype "securityStatuses" `
                                       -APIVersion $AzureSecStatus.APIVersion -Verbosity $Verbosity -WriteLog $WriteLog
        
        
        $AllVMs = $AllStatus | Where-Object {$_.properties.type -eq 'VirtualMachine'}
        #Get primary object
        $AllSecBaseline = @()
        if($AllVMs){
            foreach($vm in $AllVMs){
                Write-AzucarMessage -WriteLog $WriteLog -Message ("Searching for Security baseline in {0}..." -f $vm.name) `
                                    -Plugin $PluginName -Verbosity $Verbosity -IsVerbose
                $WorkSpace = $vm.properties.workspaces | Select-Object id, customerId
                $query = ('let query = \nSecurityBaseline\n| where AnalyzeResult == \"{0}\" and Computer=~ \"{1}\" \n| summarize AggregatedValue = dcount(BaselineRuleId) by BaselineRuleId, RuleSeverity, SourceComputerId, BaselineId, BaselineType, OSName, CceId, BaselineRuleType, Description, RuleSetting, ExpectedResult, ActualResult | sort by RuleSeverity asc| limit 1000000000; query' -f "Failed", $vm.name)
                #Convert to JSON data
                $requestBody = @{"query" = $query;}
                $JsonData = $requestBody | ConvertTo-Json -Depth 50 | % { [System.Text.RegularExpressions.Regex]::Unescape($_) }
                $URI = ("{0}{1}/{2}?api-version={3}" -f $Instance.ResourceManager, $WorkSpace.id, "api/query","2017-01-01-preview")
                #POST Request
                $AllSecurityBaseline = Get-AzSecRMObject -Manual -OwnQuery $URI -Authentication $RMAuth -Data $JsonData -Verbosity $Verbosity -Method "POST" -WriteLog $WriteLog
                if($AllSecurityBaseline.Tables[0].Rows){
                    Write-AzucarMessage -WriteLog $WriteLog -Message ("Getting Security baseline elements for {0}..." -f $vm.name) `
                                        -Plugin $PluginName -Verbosity $Verbosity -IsVerbose
                    foreach ($row in $AllSecurityBaseline.Tables[0].Rows){
                        $AzucarSecurityBaseline = New-Object -TypeName PSCustomObject
                        $AzucarSecurityBaseline | Add-Member -type NoteProperty -name ServerName -value $vm.name
                        $AzucarSecurityBaseline | Add-Member -type NoteProperty -name ResourceGroupName -value $vm.id.Split("/")[4]
                        $AzucarSecurityBaseline | Add-Member -type NoteProperty -name SourceComputerId -value $row[2]
                        $AzucarSecurityBaseline | Add-Member -type NoteProperty -name RuleSeverity -value $row[1]
                        $AzucarSecurityBaseline | Add-Member -type NoteProperty -name BaselineRuleId -value $row[0]
                        $AzucarSecurityBaseline | Add-Member -type NoteProperty -name BaselineType -value $row[4]
                        $AzucarSecurityBaseline | Add-Member -type NoteProperty -name OSName -value $row[5]
                        $AzucarSecurityBaseline | Add-Member -type NoteProperty -name CceId -value $row[6]
                        $AzucarSecurityBaseline | Add-Member -type NoteProperty -name BaselineRuleType -value $row[7]
                        $AzucarSecurityBaseline | Add-Member -type NoteProperty -name Description -value $row[8]
                        $AzucarSecurityBaseline | Add-Member -type NoteProperty -name RuleSetting -value $row[9]
                        $AzucarSecurityBaseline | Add-Member -type NoteProperty -name ExpectedResult -value $row[10]
                        $AzucarSecurityBaseline | Add-Member -type NoteProperty -name ActualResult -value $row[11]
                        #Decorate Object
                        $AzucarSecurityBaseline.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.SecurityBaseline') 
                        $AllSecBaseline+=$AzucarSecurityBaseline
                    }
                }
            }
        }
    }
    End{
        if($AllSecBaseline){
            #Work with SyncHash
            $SyncServer.$($PluginName)=$AllSecBaseline
            $AllSecBaseline.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.SecurityBaseline')
            #Create custom object for store data
            $SecurityBaseline = New-Object -TypeName PSCustomObject
            $SecurityBaseline | Add-Member -type NoteProperty -name Section -value $Section
            $SecurityBaseline | Add-Member -type NoteProperty -name Data -value $AllSecBaseline
            #Add VM data to object
            if($SecurityBaseline){
                $ReturnPluginObject | Add-Member -type NoteProperty -name SecurityBaseline -value $SecurityBaseline
            }
        }
        else{
            Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzureADGeneralQueryEmptyMessage -f "Security Baseline", $AzureObject.TenantID) `
                                -Plugin $PluginName -Verbosity $Verbosity -IsWarning
        }
    }