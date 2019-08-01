Function Generate-Excel{
[cmdletbinding()]
    Param (
        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Alias('AzureData')]
        [Object]$AllData,
        
        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Alias('Formatting')]
        [Object]$TableFormatting,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Alias('Style')]
        [Object]$HeaderStyle,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Alias('Settings')]
        [Object]$ExcelSettings,

        [parameter()]
        [string]$RootPath,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [String]$TenantID

    )
    Begin{
        Function Create-ExcelFolderReport{
                [cmdletbinding()]
                Param (
                    [parameter()]
                    [string]$RootPath
                )
            $target = "$($RootPath)\ExcelReport"
            if (!(Test-Path -Path $target)){
                $tmpdir = New-Item -ItemType Directory -Path $target
                Write-Verbose ($message.FolderReportMessageCreation -f $target) @VerboseOptions
                return $target}
            else{
            Write-Verbose ($message.DirectoryAlreadyExistsWarning -f $target) @VerboseOptions
            return $target
            }
       }   
            
    }
    Process{
        if($AllData -and $ExcelSettings -and $TableFormatting){
            Write-Host ($message.EXCELTaskCreateReportMessage -f $TenantID) -ForegroundColor Magenta
            #Create Excel object
            $isDebug = [System.Convert]::ToBoolean($ExcelSettings.excelSettings.Debug)
            Create-Excel -ExcelDebugging $isDebug
            if($ExcelSettings){
                # Create About Page
			    Create-About -ExcelSettings $ExcelSettings
            }
            #Set Table Formatting
            if($TableFormatting.tableFormatting.Style){
                $FormatTable = $TableFormatting.tableFormatting.Style
            }
            else{
                $FormatTable = $false
            }
            #Get Language Settings
            [String]$Language = Get-ExcelLanguage 
            if ($Language){
                #Try to get config data
                if($HeaderStyle.HeaderStyle.$Language){
                    #Detected language
                    Write-Verbose ($message.ExcelLocaleDetected -f $Language) @VerboseOptions
                    $Header = $HeaderStyle.HeaderStyle.$Language
                }
                else{
                    $Header = $false
                }
            }
            else{
                $Header = $false
            }
            #Populate data into Excel sheets
            $AllData | % {
                Foreach ($newDataSheet in $_.psobject.Properties){
                    if($newDataSheet.Name -and $newDataSheet.Value){
                            Write-Verbose ($message.ExcelExportToANewSheetMessage -f $newDataSheet.name) @VerboseOptions
                            $Data =  $newDataSheet.Value.Data
                            $Title = $newDataSheet.Name
                            $TableTitle = $newDataSheet.name
                            $freeze = $True
                            Create-CSV2Table -Data $Data -Title $Title -TableTitle $TableTitle `
                                               -TableStyle $FormatTable -isFreeze $freeze `
                                               -iconColumnName $null| Out-Null


                    }
                }
            }
            #Add Some charts to Excel
            $DirectoryRoles = $AllData | ? { $_.psobject.Properties.Name -eq "DirectoryRoles" }
            $AllDRData = $DirectoryRoles.DirectoryRoles.Data
            $DRChart = @{}
            if($AllDRData){
                foreach ($group in $AllDRData){
                    if($group.members -eq 0){
                        continue
                    }
                    else{
                        $DRChart.Add($group.displayName, $group.Members)  
                    }
                }
                if($DRChart){
                    $Data =  $DRChart
                    $ShowHeaders = $True
                    $ShowTotals = $True
                    $MyHeaders = @('Type of group','Number of Members')
                    $Title = "Directory Roles Chart"
                    $TableName = "Directory Roles Graph"
                    $Position = @(1,1)
                    $isnewSheet = [System.Convert]::ToBoolean($True)
                    $addNewChart = [System.Convert]::ToBoolean($True)
                    $ChartType = "xlColumnClustered"
                    $HasDatatable = [System.Convert]::ToBoolean($True)
                    $chartStyle = 34
                    $chartTitle = "Directoryroles Members"
                    #Create new table with data
                    Create-Table -ShowTotals $ShowTotals -ShowHeaders $ShowHeaders -Data $Data `
                                -SheetName $Title -TableTitle $TableName -Position $Position `
                                -Header $MyHeaders -isNewSheet $isnewSheet -addNewChart $addNewChart `
                                -ChartType $ChartType -ChartTitle $chartTitle `
                                -ChartStyle $chartStyle -HasDataTable $HasDatatable `
                                -HeaderStyle $Header | Out-Null
                }
            }
            #Add some charts to Excel
            $RBAC = $AllData | ? { $_.psobject.Properties.Name -eq "azure_rbac_users" }
            if($RBAC){
                $RBACChart = @{}
                #Group for each object for count values
                $RBAC.azure_rbac_users.Data | Group-Object RoleName | ForEach-Object {$RBACChart.Add($_.Name,@($_.Count))}
                if($RBACChart){
                    #Prepare Chart
                    $Data =  $RBACChart
                    $ShowHeaders = $True
                    $ShowTotals = $True
                    $MyHeaders = @('Role Name','Number of Members')
                    $Title = "Role Based Access Control Chart"
                    $TableName = "RBAC Graph"
                    $Position = @(1,1)
                    $isnewSheet = [System.Convert]::ToBoolean($True)
                    $addNewChart = [System.Convert]::ToBoolean($True)
                    $ChartType = "xlBarClustered"
                    $HasDatatable = [System.Convert]::ToBoolean($True)
                    $chartStyle = 34
                    $chartTitle = "Role Based Access Control Members"
                    #Create new table with data
                    Create-Table -ShowTotals $ShowTotals -ShowHeaders $ShowHeaders -Data $Data `
                                -SheetName $Title -TableTitle $TableName -Position $Position `
                                -Header $MyHeaders -isNewSheet $isnewSheet -addNewChart $addNewChart `
                                -ChartType $ChartType -ChartTitle $chartTitle `
                                -ChartStyle $chartStyle -HasDataTable $HasDatatable `
                                -HeaderStyle $Header | Out-Null

                }
            }
            #Add some charts to Excel
            $Classic = $AllData | ? { $_.psobject.Properties.Name -eq "azure_classic_admins" }
            if($Classic){
                $ClassicChart = @{}
                #Group for each object for count values
                $Classic.azure_classic_admins.Data | Group-Object role | ForEach-Object {$ClassicChart.Add($_.Name,@($_.Count))}
                if($ClassicChart){
                    #Prepare Chart
                    $Data =  $ClassicChart
                    $ShowHeaders = $True
                    $ShowTotals = $True
                    $MyHeaders = @('Role Name','Number of Members')
                    $Title = "Classic Administrators Chart"
                    $TableName = "Classic Graph"
                    $Position = @(1,1)
                    $isnewSheet = [System.Convert]::ToBoolean($True)
                    $addNewChart = [System.Convert]::ToBoolean($True)
                    $ChartType = "xlBarClustered"
                    $HasDatatable = [System.Convert]::ToBoolean($True)
                    $chartStyle = 34
                    $chartTitle = "Classic Administrators Members"
                    #Create new table with data
                    Create-Table -ShowTotals $ShowTotals -ShowHeaders $ShowHeaders -Data $Data `
                                -SheetName $Title -TableTitle $TableName -Position $Position `
                                -Header $MyHeaders -isNewSheet $isnewSheet -addNewChart $addNewChart `
                                -ChartType $ChartType -ChartTitle $chartTitle `
                                -ChartStyle $chartStyle -HasDataTable $HasDatatable `
                                -HeaderStyle $Header | Out-Null

                }
            }
            #Add Baseline Data chart
            $BaselineStatus = $AllData | ? { $_.psobject.Properties.Name -eq "azure_vm_security_baseline" }
            if($BaselineStatus){
                #Group for each object for count values
                $BaselineStats = @{}
                $SecurityBaselineStats = $BaselineStatus.azure_vm_security_baseline.Data | Group-Object ServerName -AsHashTable
                if($SecurityBaselineStats){
                    foreach($rule in $SecurityBaselineStats.GetEnumerator()){
                        $Critical = 0
                        $Informational = 0
                        $Warning = 0
                        foreach($element in $rule.value){
                            switch ($element.RuleSeverity) { 
                                'Critical'
                                {
                                    $Critical+=1
                                }
                                'Informational'
                                {
                                    $Informational+=1
                                }
                                'Warning'
                                {
                                    $Warning+=1
                                }
                            }
                        }
                        $BaselineStats.Add($rule.Name,@($critical, $Informational, $Warning))
                    }
                    if($BaselineStats){
                        #Prepare Chart
                        $Data =  $BaselineStats
                        $ShowHeaders = $True
                        $ShowTotals = $True
                        $MyHeaders = @('VMName','Critical','Informational','Warning')
                        $TableName = "Security Baseline chart"
                        $Position = @(1,1)
                        $Title = "VM Security Baseline Chart"
                        $isnewSheet = [System.Convert]::ToBoolean($True)
                        $addNewChart = [System.Convert]::ToBoolean($True)
                        $ChartType = "xlColumnClustered"
                        $HasDatatable = [System.Convert]::ToBoolean($True)
                        $chartStyle = 34
                        $chartTitle = "Security Baseline Status"
                        #Create new table with data
                        Create-Table -ShowTotals $ShowTotals -ShowHeaders $ShowHeaders -Data $Data `
                                    -TableTitle $TableName -Position $Position `
                                    -Header $MyHeaders -isNewSheet $isnewSheet -addNewChart $addNewChart `
                                    -ChartType $ChartType -ChartTitle $chartTitle `
                                    -ChartStyle $chartStyle -HasDataTable $HasDatatable `
                                    -HeaderStyle $Header -SheetName $Title | Out-Null

                    }
                }
            }
            #Add Missing Patches
            $MissingPatches = $AllData | ? { $_.psobject.Properties.Name -eq "azure_vm_missing_patches" }
            if($MissingPatches){
                #Group for each object for count values
                $KBStats = @{}
                $PatchesStats = $MissingPatches.MissingPatches.Data | Group-Object ServerName -AsHashTable 
                if($PatchesStats){
                    foreach($Kbs in $PatchesStats.GetEnumerator()){
                        $Critical = 0
                        $Moderate = 0
                        $Low = 0
                        $Important = 0
                        $Security = 0
                        foreach($element in $Kbs.value){
                            switch ($element.Severity) { 
                                'Critical'
                                {
                                    $Critical+=1
                                }
                                'Security'
                                {
                                    $Security+=1
                                }
                                'Important'
                                {
                                    $Important+=1
                                }
                                'Moderate'
                                {
                                    $Moderate+=1
                                }
                                'Low'
                                {
                                    $Low+=1
                                }
                            }
                        }
                        $KBStats.Add($Kbs.Name,@($critical, $security, $important,$moderate,$low))
                    }
                    if($KBStats){
                        #Prepare Chart
                        $Data =  $KBStats
                        $ShowHeaders = $True
                        $ShowTotals = $True
                        $MyHeaders = @('VMName','Critical','Security','Important','Moderate','Low')
                        $TableName = "KBs chart"
                        $Position = @(1,1)
                        $Title = "Missing Patches Chart"
                        $isnewSheet = [System.Convert]::ToBoolean($True)
                        $addNewChart = [System.Convert]::ToBoolean($True)
                        $ChartType = "xlColumnClustered"
                        $HasDatatable = [System.Convert]::ToBoolean($True)
                        $chartStyle = 34
                        $chartTitle = "Patch Status"
                        #Create new table with data
                        Create-Table -ShowTotals $ShowTotals -ShowHeaders $ShowHeaders -Data $Data `
                                    -TableTitle $TableName -Position $Position `
                                    -Header $MyHeaders -isNewSheet $isnewSheet -addNewChart $addNewChart `
                                    -ChartType $ChartType -ChartTitle $chartTitle `
                                    -ChartStyle $chartStyle -HasDataTable $HasDatatable `
                                    -HeaderStyle $Header -SheetName $Title | Out-Null

                    }
                }
            }
            #Add Dashboard
            $VM = $AllData | ? { $_.psobject.Properties.Name -eq "azure_virtual_machines" }
            $Y = 1
            $X = 1
            $newSheet = $false
            if($VM){
                $VMStats = @{}
                #Group for each object for count values
                $VM.azure_virtual_machines.Data | Group-Object encryptionsettingsenabled | ForEach-Object {$VMStats.Add($_.Name,@($_.Count))}
                if($VMStats){
                    #Prepare Chart
                    $Data =  $VMStats
                    $ShowHeaders = $True
                    $ShowTotals = $True
                    $MyHeaders = @('VM Encryption Settins','Number of VM')
                    $Title = "Azucar Dashboard"
                    $TableName = "VM Encryption chart"
                    $Position = @($X,$Y)
                    $isnewSheet = [System.Convert]::ToBoolean($True)
                    $addNewChart = [System.Convert]::ToBoolean($True)
                    $ChartType = "xlPie"
                    $HasDatatable = [System.Convert]::ToBoolean($True)
                    $chartStyle = 34
                    $chartTitle = "Virtual Machine Encryption Settings"
                    #Create new table with data
                    Create-Table -ShowTotals $ShowTotals -ShowHeaders $ShowHeaders -Data $Data `
                                -SheetName $Title -TableTitle $TableName -Position $Position `
                                -Header $MyHeaders -isNewSheet $isnewSheet -addNewChart $addNewChart `
                                -ChartType $ChartType -ChartTitle $chartTitle `
                                -ChartStyle $chartStyle -HasDataTable $HasDatatable `
                                -HeaderStyle $Header | Out-Null

                    $newSheet = $true
                    $Y+=5
                }
            }
            #Add Databases
            $AllDatabases = $AllData | ? { $_.psobject.Properties.Name -eq "azure_sql_databases" }
            if($AllDatabases){
                $TDEStats = @{}
                $Encryption = @{}
                $Auditing = @{}
                #Group for each object for count values
                $AllDatabases.azure_sql_databases.Data | ? {$_.DatabaseName -ne "master"} | Group-Object threatDetectionPolicy | ForEach-Object {$TDEStats.Add($_.Name,@($_.Count))}
                $AllDatabases.azure_sql_databases.Data | ? {$_.DatabaseName -ne "master"} | Group-Object databaseEncryptionStatus | ForEach-Object {$Encryption.Add($_.Name,@($_.Count))}
                $AllDatabases.azure_sql_databases.Data | ? {$_.DatabaseName -ne "master"} | Group-Object databaseAuditingState | ForEach-Object {$Auditing.Add($_.Name,@($_.Count))}
                if($TDEStats){
                    #Prepare Chart
                    $Data =  $TDEStats
                    $ShowHeaders = $True
                    $ShowTotals = $True
                    $MyHeaders = @('TDE Status','Count')
                    $TableName = "TDE chart"
                    $Position = @($X,$Y)
                    if($newSheet){$isnewSheet = [System.Convert]::ToBoolean($false);$Title=$null}
                    else{
                        $Title = "Azucar Dashboard"
                        $isnewSheet = [System.Convert]::ToBoolean($True)
                    }
                    $addNewChart = [System.Convert]::ToBoolean($True)
                    $ChartType = "xlColumnClustered"
                    $HasDatatable = [System.Convert]::ToBoolean($True)
                    $chartStyle = 34
                    $chartTitle = "Threat Detection Policy Status"
                    #Create new table with data
                    Create-Table -ShowTotals $ShowTotals -ShowHeaders $ShowHeaders -Data $Data `
                                -TableTitle $TableName -Position $Position `
                                -Header $MyHeaders -isNewSheet $isnewSheet -addNewChart $addNewChart `
                                -ChartType $ChartType -ChartTitle $chartTitle `
                                -ChartStyle $chartStyle -HasDataTable $HasDatatable `
                                -HeaderStyle $Header -SheetName $Title | Out-Null
                                    
                    $newSheet = $true
                    $Y+=5
                }
                if($Encryption){
                    #Prepare Chart
                    $Data =  $Encryption
                    $ShowHeaders = $True
                    $ShowTotals = $True
                    $MyHeaders = @('Encryption Status','Count')
                    $TableName = "Encryption chart"
                    $Position = @($X,$Y)
                    if($newSheet){$isnewSheet = [System.Convert]::ToBoolean($false);$Title=$null}
                    else{
                        $Title = "Azucar Dashboard"
                        $isnewSheet = [System.Convert]::ToBoolean($True)
                    }
                    $addNewChart = [System.Convert]::ToBoolean($True)
                    $ChartType = "xlColumnClustered"
                    $HasDatatable = [System.Convert]::ToBoolean($True)
                    $chartStyle = 34
                    $chartTitle = "Database Encryption Status"
                    #Create new table with data
                    Create-Table -ShowTotals $ShowTotals -ShowHeaders $ShowHeaders -Data $Data `
                                -TableTitle $TableName -Position $Position `
                                -Header $MyHeaders -isNewSheet $isnewSheet -addNewChart $addNewChart `
                                -ChartType $ChartType -ChartTitle $chartTitle `
                                -ChartStyle $chartStyle -HasDataTable $HasDatatable `
                                -HeaderStyle $Header -SheetName $Title | Out-Null
                                    
                    $newSheet = $true
                    $Y+=5
                    if($Y -ge 11){
                        $X += 17
                        $Y = 1
                    }
                }
                if($Auditing){
                    #Prepare Chart
                    $Data =  $Auditing
                    $ShowHeaders = $True
                    $ShowTotals = $True
                    $MyHeaders = @('Database Auditing','Count')
                    $TableName = "Auditing chart"
                    $Position = @($X,$Y)
                    if($newSheet){$isnewSheet = [System.Convert]::ToBoolean($false);$Title=$null}
                    else{
                        $Title = "Azucar Dashboard"
                        $isnewSheet = [System.Convert]::ToBoolean($True)
                    }
                    $addNewChart = [System.Convert]::ToBoolean($True)
                    $ChartType = "xlColumnClustered"
                    $HasDatatable = [System.Convert]::ToBoolean($True)
                    $chartStyle = 34
                    $chartTitle = "Database Auditing Status"
                    #Create new table with data
                    Create-Table -ShowTotals $ShowTotals -ShowHeaders $ShowHeaders -Data $Data `
                                -TableTitle $TableName -Position $Position `
                                -Header $MyHeaders -isNewSheet $isnewSheet -addNewChart $addNewChart `
                                -ChartType $ChartType -ChartTitle $chartTitle `
                                -ChartStyle $chartStyle -HasDataTable $HasDatatable `
                                -HeaderStyle $Header -SheetName $Title | Out-Null
                                    
                    $newSheet = $true
                    $Y+=5
                    if($Y -ge 11){
                        $X += 17
                        $Y = 1
                    }
                } 
            }
        }
        #Add Storage Accounts
        $StorageAccounts = $AllData | ? { $_.psobject.Properties.Name -eq "azure_storage_accounts" }
        if($StorageAccounts){
            $StorageBlobStats = @{}
            $StorageFileStats = @{}
            #Group for each object for count values
            $StorageAccounts.azure_storage_accounts.Data | Group-Object isBlobEncrypted | ForEach-Object {$StorageBlobStats.Add($_.Name,@($_.Count))}
            $StorageAccounts.azure_storage_accounts.Data | Group-Object isFileEncrypted | ForEach-Object {$StorageFileStats.Add($_.Name,@($_.Count))}
            if($StorageBlobStats){
                #Prepare Chart
                $Data =  $StorageBlobStats
                $ShowHeaders = $True
                $ShowTotals = $True
                $MyHeaders = @('Storage Account Blob Encryption','Number of StorageAccounts')
                if($newSheet){$isnewSheet = [System.Convert]::ToBoolean($false);$Title=$null}
                else{
                    $Title = "Azucar Dashboard"
                    $isnewSheet = [System.Convert]::ToBoolean($True)
                }
                $TableName = "StorageAccount Blob chart"
                $Position = @($X,$Y)
                $addNewChart = [System.Convert]::ToBoolean($True)
                $ChartType = "xlColumnClustered"
                $HasDatatable = [System.Convert]::ToBoolean($True)
                $chartStyle = 34
                $chartTitle = "Storage Account Blob Encryption Settings"
                #Create new table with data
                Create-Table -ShowTotals $ShowTotals -ShowHeaders $ShowHeaders -Data $Data `
                            -SheetName $Title -TableTitle $TableName -Position $Position `
                            -Header $MyHeaders -isNewSheet $isnewSheet -addNewChart $addNewChart `
                            -ChartType $ChartType -ChartTitle $chartTitle `
                            -ChartStyle $chartStyle -HasDataTable $HasDatatable `
                            -HeaderStyle $Header | Out-Null

                $newSheet = $true
                $Y+=5
                if($Y -ge 11){
                    $X += 17
                    $Y = 1
                }
            }
            if($StorageFileStats){
                #Prepare Chart
                $Data =  $StorageFileStats
                $ShowHeaders = $True
                $ShowTotals = $True
                $MyHeaders = @('Storage Account File Encryption','Number of StorageAccounts')
                if($newSheet){$isnewSheet = [System.Convert]::ToBoolean($false);$Title=$null}
                else{
                    $Title = "Azucar Dashboard"
                    $isnewSheet = [System.Convert]::ToBoolean($True)
                }
                $TableName = "StorageAccount File chart"
                $Position = @($X,$Y)
                $addNewChart = [System.Convert]::ToBoolean($True)
                $ChartType = "xlColumnClustered"
                $HasDatatable = [System.Convert]::ToBoolean($True)
                $chartStyle = 34
                $chartTitle = "Storage Account File Encryption Settings"
                #Create new table with data
                Create-Table -ShowTotals $ShowTotals -ShowHeaders $ShowHeaders -Data $Data `
                            -SheetName $Title -TableTitle $TableName -Position $Position `
                            -Header $MyHeaders -isNewSheet $isnewSheet -addNewChart $addNewChart `
                            -ChartType $ChartType -ChartTitle $chartTitle `
                            -ChartStyle $chartStyle -HasDataTable $HasDatatable `
                            -HeaderStyle $Header | Out-Null

                $newSheet = $true
                $Y+=5
                if($Y -ge 11){
                    $X += 17
                    $Y = 1
                }
            }
        }
        #Delete Sheet1 and create index
		$Excel.WorkSheets.Item($Excel.WorkSheets.Count).Delete() | Out-Null
        Create-Index -ExcelSettings $ExcelSettings
    }
    End{
        #Create Report Folder
        $ReportPath = Create-ExcelFolderReport -RootPath $RootPath
        Write-Verbose ($message.FolderReportMessageCreation -f $ReportPath) @VerboseOptions

        #Save Excel
        Save-Excel -Path $ReportPath
        #Release Excel Object
        Release-Reference $Excel $WorkSheet $WorkBook
        Release-ExcelObject
    }
}