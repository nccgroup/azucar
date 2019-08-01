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
        #Import Global vars
        $LogPath = $AzureObject.LogPath
        Set-Variable LogPath -Value $LogPath -Scope Global
    }
    Process{
        $PluginName = $AzureObject.PluginName
        $AzureSecStatus = $AzureObject.AzureConfig.SecurityStatuses
        $Section = $AzureObject.AzureSection
        Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzucarADGeneralTaskMessage -f "Missing Patches", $bgRunspaceID, $PluginName, $AzureObject.TenantID) `
                                -Plugin $PluginName -IsHost -Color Green
        #Retrieve instance
        $Instance = $AzureObject.Instance
        #Retrieve Azure Resource Management Auth
        $RMAuth = $AzureObject.AzureConnections.ResourceManager
        #List all VMs
        $AllStatus = Get-AzSecRMObject -Instance $Instance -Authentication $RMAuth `
                                       -Provider $AzureSecStatus.Provider -Objectype "securityStatuses" `
                                       -APIVersion $AzureSecStatus.APIVersion -Verbosity $Verbosity -WriteLog $WriteLog
        
        $AllVMs = $AllStatus | Where-Object {$_.properties.type -eq 'VirtualMachine' -or $_.properties.type -eq 'ClassicVirtualMachine'}
        #Get primary object
        $AllMissingPatches = @()
        if($AllVMs){
            foreach($vm in $AllVMs){
                $query = ("set query_take_max_records=10001;set truncationmaxsize=67108864;\nUpdate | where Computer == '{0}' and UpdateState =~ 'Needed'" -f $vm.name)
                $requestBody = @{"query" = $query;}
                #Convert to JSON data
                $MissingUpdatesJSON = $requestBody | ConvertTo-Json | % { [System.Text.RegularExpressions.Regex]::Unescape($_) }

                $isAgentInstalled = $vm.properties.resourceDetails | Where-Object {$_.name -eq 'VM Agent installed'} | Select-Object -ExpandProperty value
                $isMonitoringAgentInstalled = $vm.properties.resourceDetails | Where-Object {$_.name -eq 'Monitoring agent extension installed'} | Select-Object -ExpandProperty value
                $osType = $vm.properties.resourceDetails | Where-Object {$_.name -eq 'OS Type'} | Select-Object -ExpandProperty value
                if($isAgentInstalled -ne 'On'){
                    Write-AzucarMessage -WriteLog $WriteLog -Message ("Missing VMAgent for {0}..." -f $vm.name) `
                                        -Plugin $PluginName -Verbosity $Verbosity -IsVerbose
                }
                if($isMonitoringAgentInstalled -ne 'On'){
                    Write-AzucarMessage -WriteLog $WriteLog -Message ("Missing monitoring agent extension for {0}..." -f $vm.name) `
                                        -Plugin $PluginName -Verbosity $Verbosity -IsVerbose
                }
                if($isMonitoringAgentInstalled -ne 'On'){
                    Write-AzucarMessage -WriteLog $WriteLog -Message ("Missing monitoring agent extension for {0}..." -f $vm.name) `
                                        -Plugin $PluginName -Verbosity $Verbosity -IsVerbose
                }
                Write-AzucarMessage -WriteLog $WriteLog -Message ("Searching for Missing Patches in {0} {1} Virtual Machine..." -f $vm.name, $osType) `
                                    -Plugin $PluginName -Verbosity $Verbosity -IsVerbose

                #Construct Query
                $WorkSpaceId = $vm.properties.resourceDetails | Where-Object {$_.name -eq 'Reporting workspace customer id'} | Select-Object -ExpandProperty value
                $WorkSpacePath = $vm.properties.resourceDetails | Where-Object {$_.name -eq 'Reporting workspace azure id'} | Select-Object -ExpandProperty value
                $URI = ("{0}{1}/{2}?api-version={3}" -f $Instance.ResourceManager, $WorkSpacePath, "api/query","2017-01-01-preview")
                try{
                    #POST Request
                    $MissingPatches = Get-AzSecRMObject -Manual -OwnQuery $URI -Authentication $RMAuth `
                                                        -Data $MissingUpdatesJSON -Verbosity $Verbosity `
                                                        -Method "POST" -WriteLog $WriteLog
  
                    $columns = $MissingPatches.tables | Where-Object {$_.TableName -eq 'Table_0'} | Select-Object -ExpandProperty Columns
                    $rows = $MissingPatches.tables | Where-Object {$_.TableName -eq 'Table_0'} | Select-Object -ExpandProperty Rows
                    if($rows -and $columns){
                        foreach ($update in $rows){
                            $AzucarMissingPatch = New-Object -TypeName PSCustomObject
                            $AzucarMissingPatch | Add-Member -type NoteProperty -name ServerName -value $vm.name
                            $AzucarMissingPatch | Add-Member -type NoteProperty -name ResourceGroupName -value $vm.id.Split("/")[4]
                            for ($counter=0; $counter -lt $update.Length; $counter++){
                                if($columns[$counter].ColumnName -eq 'KBID'){
                                    $AzucarMissingPatch | Add-Member -type NoteProperty -name KBID -value ("https://support.microsoft.com/en-us/help/{0}" -f $update[$counter])
                                }
                                else{
                                    $AzucarMissingPatch | Add-Member -type NoteProperty -name $columns[$counter].ColumnName -value $update[$counter]
                                }
                            }
                            $AllMissingPatches+=$AzucarMissingPatch
                        }
                    }
                }
                catch{
                    Write-AzucarMessage -WriteLog $WriteLog -Message ("Unable to create query for {0}. OsType is {1}" -f $vm.name. $osType) `
                                        -Plugin $PluginName -Verbosity $Verbosity -IsVerbose 
                }               
            } 
        }
    }
    End{
        if($AllMissingPatches){
            #Work with SyncHash
            $SyncServer.$($PluginName)=$AllMissingPatches
            $AllMissingPatches.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.AllMissingPatches')
            #Create custom object for store data
            $MPatches = New-Object -TypeName PSCustomObject
            $MPatches | Add-Member -type NoteProperty -name Section -value $Section
            $MPatches | Add-Member -type NoteProperty -name Data -value $AllMissingPatches
            #Return Object
            if($MPatches){
                $ReturnPluginObject | Add-Member -type NoteProperty -name azure_vm_missing_patches -value $MPatches
            }
        }
        else{
            Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzureADGeneralQueryEmptyMessage -f "Missing Patches", $AzureObject.TenantID) `
                                -Plugin $PluginName -Verbosity $Verbosity -IsWarning
        }
    }