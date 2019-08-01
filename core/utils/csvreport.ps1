Function Generate-CSV{
[cmdletbinding()]
    Param (
        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [String]$TenantID,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Object]$ObjectData,
        
        [parameter()]
        [string]$RootPath

    )

    Begin{
          Function Create-CSVFolderReport{
            [cmdletbinding()]
                Param (        
                    [parameter()]
                    [string]$RootPath,

                    [parameter()]
                    [string]$DirectoryName

                )
                if($DirectoryName){
                    $target = "{0}\{1}" -f $RootPath, $DirectoryName
                }
                else{
                    $target = "{0}\{1}" -f $RootPath, "CSVReport"
                }
            if (!(Test-Path -Path $target)){
                $tmpdir = New-Item -ItemType Directory -Path $target
                Write-Verbose ($message.FolderReportMessageCreation -f $target) @VerboseOptions
                return $target}
            else{
            Write-Verbose ($message.DirectoryAlreadyExistsWarning -f $target) @VerboseOptions
            return $target
            }
       }
       ##End of function
    }
    Process{
            if($ObjectData){
                $ReportPath = Create-CSVFolderReport -RootPath $RootPath
                Write-Verbose ($message.FolderReportMessageCreation -f $ReportPath) @VerboseOptions
            }
            if($ObjectData -and $ReportPath){
                Write-Host ($message.CSVTaskCreateReportMessage -f $TenantID) -ForegroundColor Magenta
                $ObjectData | %{
                    foreach ($query in $_.psobject.Properties){
                        if($query.Name -and $query.Value){
                            Write-Verbose ($message.ExportFileToCSVMessage -f $query.Name) @VerboseOptions
                            try{
                                if($query.value.Data -and $query.value.Section){
                                    $PluginPath = Create-CSVFolderReport -RootPath $ReportPath -DirectoryName $query.value.Section
                                    $CSVFile = ("{0}\{1}.csv" -f $PluginPath,$query.Name) #($PluginPath + "\" + ([System.Guid]::NewGuid()).ToString() +$query.Name+ ".csv")
                                    $query.value.Data | Export-Csv -NoTypeInformation -Path $CSVFile
                                }
                            }
                            catch{
                                Write-Host ("Error in {0}" -f $query.Name) -ForegroundColor Yellow
                                $ErrorRecord = New-Object System.Management.Automation.ErrorRecord(
                                            (New-Object Exception($_.Exception)),
                                            $null,
                                            [System.Management.Automation.ErrorCategory]::InvalidResult,
                                            $null
                                )
                                Convert-Exception -MyError $ErrorRecord `
                                -FunctionName "Generate-CSV" -WriteLog $Global:WriteLog
                            }
                        }
                    }
                }
           }             
    }
    End{
        #Nothing to do here
    }
} 