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
                if($vm.properties.vmAgent -ne "On"){
                    Write-AzucarMessage -WriteLog $WriteLog -Message ("VMAgent disabled for {0}. Unable to get information about Missing Patches..." -f $vm.name) `
                                        -Plugin $PluginName -Verbosity $Verbosity -IsVerbose 
                }
                elseif($vm.properties.vmAgent -eq "On" -AND $vm.properties.patchScannerData.missingPatchesSecurityState -ne "Healthy"){
                    Write-AzucarMessage -WriteLog $WriteLog -Message "Potentially outdated Azure Virtual Machine detected..." `
                                        -Plugin $PluginName -Verbosity $Verbosity -IsVerbose 
                    Write-AzucarMessage -WriteLog $WriteLog -Message ("Searching for Missing Patches in {0} Azure Virtual Machine..." -f $vm.name) `
                                        -Plugin $PluginName -Verbosity $Verbosity -IsVerbose
                    #Construct Query
                    $WorkSpace = $vm.properties.workspaces | Select-Object id, customerId
                    $osType = $vm.properties.osType
                    $query = $null
                    switch ($osType){
                        'Windows'
                        {
                            $query = ('let query = Update | where OSType != \"Linux\" and UpdateState =~ \"Needed\" and iff(isnotnull(toint(Optional)), Optional == false, Optional == \"false\") == true and iff(isnotnull(toint(Approved)), Approved != false, Approved != \"false\") == true and Computer =~ \"{0}\" | summarize AggregatedValue = dcount(UpdateID) by UpdateID, SourceComputerId, Title, Classification, PublishedDate, UpdateState, Product, MSRCSeverity, KBID, RevisionNumber, Optional, RebootBehavior, MSRCBulletinID, Approved ; query' -f $vm.name) 
                        }
                        'Linux'
                        {
                            $query = ('let query = Update | where OSType == \"{0}\" and UpdateState =~ \"Needed\" and Classification == \"Critical Updates\" and Computer =~ \"{1}\" ; query' -f $osType, $vm.name) 
                        }
                    }
                    if($query){
                        $requestBody = @{"query" = $query;}
                        #Convert to JSON data
                        $JsonData = $requestBody | ConvertTo-Json -Depth 50 | % { [System.Text.RegularExpressions.Regex]::Unescape($_) }
                        $URI = ("{0}{1}/{2}?api-version={3}" -f $Instance.ResourceManager, $WorkSpace.id, "api/query","2017-01-01-preview")
                        #POST Request
                        $MissingPatches = Get-AzSecRMObject -Manual -OwnQuery $URI -Authentication $RMAuth `
                                          -Data $JsonData -Verbosity $Verbosity -Method "POST" -WriteLog $WriteLog
                        #Get if data exists
                        if($MissingPatches.Tables[0].Rows){
                            foreach ($row in $MissingPatches.Tables[0].Rows){
                                $AzucarMissingPatch = New-Object -TypeName PSCustomObject
                                $AzucarMissingPatch | Add-Member -type NoteProperty -name ServerName -value $vm.name
                                $AzucarMissingPatch | Add-Member -type NoteProperty -name ResourceGroupName -value $vm.id.Split("/")[4]
                                $AzucarMissingPatch | Add-Member -type NoteProperty -name SourceComputerId -value $row[1]
                                $AzucarMissingPatch | Add-Member -type NoteProperty -name Title -value $row[2]
                                $AzucarMissingPatch | Add-Member -type NoteProperty -name Classification -value $row[3]
                                $AzucarMissingPatch | Add-Member -type NoteProperty -name PublishedDate -value $row[4]
                                $AzucarMissingPatch | Add-Member -type NoteProperty -name UpdateState -value $row[5]
                                $AzucarMissingPatch | Add-Member -type NoteProperty -name Product -value $row[6]
                                $AzucarMissingPatch | Add-Member -type NoteProperty -name Severity -value $row[7]
                                $AzucarMissingPatch | Add-Member -type NoteProperty -name KBID -value ("https://support.microsoft.com/en-us/help/{0}" -f $row[8])
                                $AzucarMissingPatch | Add-Member -type NoteProperty -name UpdateID -value $row[0]
                                $AzucarMissingPatch | Add-Member -type NoteProperty -name RevisionNumber -value $row[9]
                                $AzucarMissingPatch | Add-Member -type NoteProperty -name Optional -value $row[10]
                                $AzucarMissingPatch | Add-Member -type NoteProperty -name RebootBehavior -value $row[11]
                                $AzucarMissingPatch | Add-Member -type NoteProperty -name MSRCBulletinID -value $row[12]
                                $AzucarMissingPatch | Add-Member -type NoteProperty -name Approved -value $row[13]
                                #Decorate Object
                                $AzucarMissingPatch.PSObject.TypeNames.Insert(0,'AzureRM.NCCGroup.MissingPatch') 
                                $AllMissingPatches+=$AzucarMissingPatch
                            }
                        }
                    }
                }
                else{
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
                $ReturnPluginObject | Add-Member -type NoteProperty -name MissingPatches -value $MPatches
            }
        }
        else{
            Write-AzucarMessage -WriteLog $WriteLog -Message ($message.AzureADGeneralQueryEmptyMessage -f "Missing Patches", $AzureObject.TenantID) `
                                -Plugin $PluginName -Verbosity $Verbosity -IsWarning
        }
    }