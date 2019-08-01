Function Generate-XML{
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
        Function Create-XMLFolderReport{
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
                    $target = "{0}\{1}" -f $RootPath, "XMLReport"
                }
            if (!(Test-Path -Path $target)){
                $tmpdir = New-Item -ItemType Directory -Path $target
                Write-Verbose ($message.FolderReportMessageCreation -f $target) 
                return $target}
            else{
            Write-Verbose ($message.DirectoryAlreadyExistsWarning -f $target) @VerboseOptions
            return $target
            }
       }
       ##End of function
       if($ObjectData){
            $ReportPath = Create-XMLFolderReport -RootPath $RootPath
            Write-Verbose ($message.FolderReportMessageCreation -f $ReportPath) @VerboseOptions
       }
    }
    Process{
            if($ObjectData -and $ReportPath){
                Write-Host ($message.XMLTaskCreateReportMessage -f $TenantID) -ForegroundColor Magenta
                $ObjectData | %{
                    foreach ($query in $_.psobject.Properties){
                        if($query.Name -and $query.Value){
                            Write-Verbose ($message.ExportFileToXMLMessage -f $query.Name) @VerboseOptions
                            try{
                                if($query.value.Data -and $query.value.Section){
                                    $PluginPath = Create-XMLFolderReport -RootPath $ReportPath -DirectoryName $query.value.Section
                                    $XMLFile = ("{0}\{1}.xml" -f $PluginPath,$query.Name) #($PluginPath + "\" + ([System.Guid]::NewGuid()).ToString() +$query.Name+ ".xml")
                                    ($query.value.Data | ConvertTo-Xml).Save($XMLFile)
                                }
                            }
                            catch{
                                $ErrorRecord = New-Object System.Management.Automation.ErrorRecord(
                                            (New-Object Exception($_.Exception)),
                                            $null,
                                            [System.Management.Automation.ErrorCategory]::InvalidResult,
                                            $null
                                )
                                Convert-Exception -MyError $ErrorRecord `
                                -FunctionName "Generate-XML" -WriteLog $Global:WriteLog
                            }
                        }
                    }
                }
            }
        }
}