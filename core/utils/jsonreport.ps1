Function Generate-Json{
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
        function ConvertTo-Json20([object] $AllItems){
            add-type -assembly system.web.extensions
            $JavaScriptSerializer = new-object system.web.script.serialization.javascriptSerializer
            $JavaScriptSerializer.MaxJsonLength = [System.Int32]::MaxValue
            $AllJsonResults = @()
            foreach ($item in $AllItems){
                $TmpDict = @{}
                $item.psobject.properties | Foreach { $TmpDict[$_.Name] = $_.Value }
                
                $AllJsonResults+=$JavaScriptSerializer.Serialize($TmpDict)
            }
            #Return Data
            ,$AllJsonResults
        }
        Function Create-JsonFolderReport{
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
                    $target = "{0}\{1}" -f $RootPath, "JSONReport"
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
       if($ObjectData){
            $ReportPath = Create-JsonFolderReport -RootPath $RootPath
            Write-Verbose ($message.FolderReportMessageCreation -f $ReportPath) @VerboseOptions
       }
    }
    Process{
            if($ObjectData -and $ReportPath){
                Write-Host ($message.JSONTaskCreateReportMessage -f $TenantID) -ForegroundColor Magenta
                $ObjectData | %{
                    foreach ($query in $_.psobject.Properties){
                        if($query.Name -and $query.Value){
                            Write-Verbose ($message.ExportFileToJSONMessage -f $query.Name) @VerboseOptions
                            try{
                                if($query.value.Data -and $query.value.Section){
                                    $PluginPath = Create-JsonFolderReport -RootPath $ReportPath -DirectoryName $query.value.Section
                                    $JSONFile = ("{0}\{1}.json" -f $PluginPath,$query.Name) #($PluginPath + "\" + ([System.Guid]::NewGuid()).ToString() +$query.Name+ ".json")
                                    $output = ConvertTo-Json $query.value.Data
                                    Set-Content $JSONFile $output
                                    #$output | Out-File -FilePath $JSONFile
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
                                -FunctionName "Generate-Json" -WriteLog $Global:WriteLog
                            }
                        }
                    }
                }
            }
        }
}