Function Get-DefaultBrowser{
    Begin{
        $Http = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice').ProgId
        $Https = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice').ProgId
    }
    Process{
        $BrowserChoice = @{
                            "HTTP" = $Http;
                            "HTTPS" = $Https;
        }
    }
    End{
        return $BrowserChoice
    }
}

Function Set-DefaultBrowser{
    Param (
        [parameter(Mandatory=$false, ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [System.Collections.Hashtable]$DefaultBrowser,

        [Parameter(Mandatory=$false, HelpMessage="Set default browser to Internet Explorer")]
	    [Switch]$IE
    )
    Begin{
        if($IE -AND (Test-Path -Path 'HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice')){
            Write-AzucarMessage -Message $message.IESettingsHTTPMessage -Plugin "Set-DefaultBrowser" -IsVerbose -Verbosity $VerboseOptions -WriteLog $Global:WriteLog
            Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice' -name ProgId -Value IE.HTTP
            Write-AzucarMessage -Message $message.IESettingsHTTPSMessage -Plugin "Set-DefaultBrowser" -IsVerbose -Verbosity $VerboseOptions -WriteLog $Global:WriteLog
            Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice' -name ProgId -Value IE.HTTPS
        }
    }
    Process{
        if(-NOT $IE -AND (Test-Path -Path 'HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice')){
            if($DefaultBrowser.ContainsKey("http")){
                Write-AzucarMessage -Message ("Establishing default web browser {0} for HTTP..." -f $DefaultBrowser.http) -Plugin "Set-DefaultBrowser" -IsVerbose -Verbosity $VerboseOptions -WriteLog $Global:WriteLog
                Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice' -name ProgId -Value $DefaultBrowser.http
            }
            if($DefaultBrowser.ContainsKey("https")){
                Write-AzucarMessage -Message ("Establishing default web browser {0} for HTTPS..." -f $DefaultBrowser.http) -Plugin "Set-DefaultBrowser" -IsVerbose -Verbosity $VerboseOptions -WriteLog $Global:WriteLog
                Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice' -name ProgId -Value $DefaultBrowser.https
            }
        }
    }
    End{
        #Nothing to do here
    }
}

#Write .NET HTTP Request exception to a friendly message
Function Get-AzWebRequestException{
    Param (
        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Object]$ExceptionError,

        [Parameter(Mandatory=$false, HelpMessage="Save exception in log file")]
	    [Bool] $WriteLog,

        [Parameter(Mandatory=$false, HelpMessage="Save exception in log file")]
	    [String] $FunctionName,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [System.Collections.Hashtable]$Verbosity
    )
    Begin{
        #Get Exception Body
        $reader = [System.IO.StreamReader]::new($ExceptionError.Exception.Response.GetResponseStream())
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd()
    }
    Process{
        if($responseBody -AND $WriteLog -AND $Verbosity){
            Write-AzucarMessage -Message $responseBody -Plugin $FunctionName -IsDebug -Verbosity $Verbosity -WriteLog $WriteLog
        }
        else{
            Write-Warning -Message $responseBody 
        }
    }
    End{
        #Nothing to do here
    }
}

#Convert exception to a friendly message
#Notes for write http://9to5it.com/powershell-logging-function-library/
Function Convert-Exception{
    Param (
        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Object]$MyError,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [String]$FunctionName,

        [Parameter(Mandatory=$false, HelpMessage="Save exception in log file")]
	    [Bool] $WriteLog

        )

    Begin{
        #Convert error and save in PsObject
        $ErrorHandling = New-Object -TypeName PSCustomObject
        $ErrorHandling | Add-Member -type NoteProperty -name Message -value $MyError.Exception.Message
        $ErrorHandling | Add-Member -type NoteProperty -name FunctionName -value $FunctionName
        $ErrorHandling | Add-Member -type NoteProperty -name LineNumber -value $MyInvocation.ScriptLineNumber
    }
    Process{
        if($WriteLog){
            Write-Log ("[Exception][{0}][{1}]:{2}" -f $ErrorHandling.FunctionName,$ErrorHandling.LineNumber, $ErrorHandling.Message)
        }
        Write-Host ("[Exception][{0}][{1}]:{2}" -f $ErrorHandling.FunctionName,$ErrorHandling.LineNumber, $ErrorHandling.Message)`
                    -ForegroundColor Red
    }
    End{
        #Nothing to do here
    }

}

function Write-AzucarMessage {
    [CmdletBinding(DefaultParameterSetName = 'Verbose')]
    param (
        ## Message to send to the Verbose stream
        [Parameter(ValueFromPipeline, ParameterSetName = 'Verbose')]
        [Parameter(ValueFromPipeline, ParameterSetName = 'Warning')]
        [Parameter(ValueFromPipeline, ParameterSetName = 'Debug')]
        [Parameter(ValueFromPipeline, ParameterSetName = 'Host')]
        [ValidateNotNullOrEmpty()]
        [System.String] $Message,

        ## Azucar Plugin name
        [Parameter(ValueFromPipelineByPropertyName)]
        [System.String] $Plugin,

        ## Redirect message to the Warning stream
        [Parameter(ParameterSetName = 'Warning')]
        [System.Management.Automation.SwitchParameter] $IsWarning,

        ## Redirect message to the Debug stream
        [Parameter(ParameterSetName = 'Debug')]
        [System.Management.Automation.SwitchParameter] $IsDebug,

        ## Redirect message to the Verbose stream
        [Parameter(ParameterSetName = 'Verbose')]
        [System.Management.Automation.SwitchParameter] $IsVerbose,

        ## Redirect message to the Host stream
        [Parameter(ParameterSetName = 'Host')]
        [System.Management.Automation.SwitchParameter] $IsHost,

        [Parameter(Mandatory=$false, HelpMessage="Save exception in log file")]
	    [Bool] $WriteLog,

        ## Color
        [Parameter(ValueFromPipelineByPropertyName)]
        [System.String] $Color = "Magenta",

        ## Verbosity
        [Parameter(Mandatory=$false, HelpMessage="VerbosityOptions")]
        [System.Collections.Hashtable]$Verbosity = @{Verbose=$false}
    )
    process {

        if ([System.String]::IsNullOrEmpty($Plugin)) {
            $Plugin = 'UnkNown';
        }        
        $date = Get-Date;
        $formattedMessage = '[{0}] [{1}] - {2}' -f $date.ToString('HH:mm:ss:fff'), $Plugin, $Message;
        switch ($PSCmdlet.ParameterSetName) {
            'Warning' { Write-Warning -Message $formattedMessage; }
            'Debug' {if ($Verbosity.Debug -eq $true){$DebugPreference = 'Continue'; Write-Debug -Message $formattedMessage;}}
            'Verbose' { Write-Verbose -Message $formattedMessage @Verbosity }
            'Host' { Write-Host $formattedMessage -ForegroundColor $Color }
            Default { Write-Host $formattedMessage -ForegroundColor $Color }
        }
        #Write to log file
        if($WriteLog){
            Write-Log -Message $formattedMessage
        }


    } #end process
} #end function WriteLog

#Create LOG folder
Function Create-LOGFolder{
    [cmdletbinding()]
    Param (
        [parameter()]
        [string]$RootPath

    )
    Begin{
        $target = ("{0}\LOG" -f $RootPath)
    }
    Process{
        if (!(Test-Path -Path $target)){
            $tmpdir = New-Item -ItemType Directory -Path $target
            Write-AzucarMessage -Message ($message.FolderCreatedMessage -f $target) -Color Magenta -Plugin Create-LOGFolder -WriteLog $Global:WriteLog
            return $target
        }
        else{
            Write-AzucarMessage -Message ($message.DirectoryAlreadyExistsMessage -f $target) -Plugin Create-LOGFolder -IsWarning -WriteLog $Global:WriteLog
            return $target
        }
    }
    End{
    }      
}
##End of function
#Start LOG file
Function Start-Logging{
    Begin{
        #Check if file exists
        $FullPath = $Global:LogPath+"\AzureReview.log"
        if((Test-Path -Path $FullPath)){ 
            Remove-Item -Path $FullPath -Force -ErrorAction SilentlyContinue
        } 
    }
    Process{
        #Create file and start logging
        $null = New-Item -Path $FullPath -ItemType File -Force
        #Add start content
        Add-Content -Path $FullPath -Value "***************************************************************************************************" 
        Add-Content -Path $FullPath -Value "Started processing at [$([DateTime]::Now)]." 
        Add-Content -Path $FullPath -Value "***************************************************************************************************" 
        Add-Content -Path $FullPath -Value "" 
        Add-Content -Path $FullPath -Value "Running script Name [$($MyInvocation.ScriptName)]." 
        Add-Content -Path $FullPath -Value "" 
        Add-Content -Path $FullPath -Value "***************************************************************************************************" 
        Add-Content -Path $FullPath -Value "" 

    }
    End{
        #Nothing to do here
    }
}
##End of function
#Write info into LOG file
Function Write-Log{
    [cmdletbinding()]
    Param (
        [parameter()]
        [string]$Message

    )
    Begin{
        #Map var to log file content   
        $FullLogPath = $Global:LogPath+"\AzureReview.log"   
    }
    Process{
        #Test if file exists
        if((Test-Path -Path $FullLogPath)){
            #Add content into log file
            Add-Content -Path $FullLogPath -Value $Message
        }
    }
    End{
        #Nothing to do here
    }
}
##End of function
#Close LOG file
Function Stop-Logging{
    Begin{
        #Map var to log file content
        $FullLogPath = ("{0}\AzureReview.log" -f $Global:LogPath)
    }
    Process{
        #Check that file exists
        if((Test-Path -Path $FullLogPath)){
        }
        
        #Add start content
        Add-Content -Path $FullLogPath -Value ""
        Add-Content -Path $FullLogPath -Value "***************************************************************************************************" 
        Add-Content -Path $FullLogPath -Value "Finished processing at  [$([DateTime]::Now)]." 
        Add-Content -Path $FullLogPath -Value "***************************************************************************************************" 
    }
    End{
        #Nothing to do here
    }
}

