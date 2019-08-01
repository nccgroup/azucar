#.NET Framework's request/response model using WebRequest Class
#https://msdn.microsoft.com/en-us/library/system.net.webrequest(v=vs.110).aspx
Function New-WebRequest{
        Param (
            [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
            [String]$Url,

            [parameter()]
            [ValidateSet("Connect","Get","Post","Head","Put")]
            [String]$Method = "GET",

            [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
            [String]$Encoding,

            [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
            [String]$UserAgent = "Azucar",

            [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
            [System.Collections.Hashtable]$Headers,

            [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
            [String]$Data,

            [Parameter(Mandatory=$false, HelpMessage="Save exception in log file")]
	        [Bool] $WriteLog,

            [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
            [System.Collections.Hashtable]$Verbosity

            )
        Begin{
            Function _New-WebResponseDetailedMessage{
                Param (
                    [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
                    [Object]$response,

                    [Parameter(Mandatory=$false, HelpMessage="Save exception in log file")]
	                [Bool] $WriteLog,

                    [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
                    [System.Collections.Hashtable]$Verbosity
                )
                
                if($response -is [System.Net.HttpWebResponse]){
                    #Response Headers
                    Write-AzucarMessage -Message ("Response-Headers: {0}" -f $response.Headers) -Plugin "New-WebRequest" -IsDebug -Verbosity $Verbosity -WriteLog $WriteLog
                    #Status Code
                    Write-AzucarMessage -Message ("Status-Code: {0}" -f [int]$response.StatusCode) -Plugin "New-WebRequest" -IsDebug -Verbosity $Verbosity -WriteLog $WriteLog
                    #Server Header
                    Write-AzucarMessage -Message ("Response-Uri: {0}" -f $response.ResponseUri) -Plugin "New-WebRequest" -IsDebug -Verbosity $Verbosity -WriteLog $WriteLog
                }
                else{
                    Write-AzucarMessage -Message ("Unknown WebResponse object: {0}" -f $response) -Plugin "New-WebRequest" -IsDebug -Verbosity $Verbosity -WriteLog $WriteLog
                }
            }

            Function _New-WebRequestException{
                Param (
                    [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
                    [Object]$Exception,

                    [Parameter(Mandatory=$false, HelpMessage="Save exception in log file")]
	                [Bool] $WriteLog,

                    [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
                    [System.Collections.Hashtable]$Verbosity
                )
                if($Exception.Exception.Response.StatusCode){
                    $StatusCode = $Exception.Exception.Response.StatusCode
                    $errorMessage = ($Exception.Exception.Message).ToString().Trim();
                    #Get Exception Body Message
                    $reader = [System.IO.StreamReader]::new($Exception.Exception.Response.GetResponseStream())
                    $reader.BaseStream.Position = 0
                    $reader.DiscardBufferedData()
                    $responseBody = $reader.ReadToEnd()
                    Write-AzucarMessage -Message ("[{0}]: {1}" -f $StatusCode, $errorMessage) `
                                        -Plugin "New-WebRequest" -IsDebug -Verbosity $Verbosity `
                                        -WriteLog $WriteLog

                    Write-AzucarMessage -Message ("[Url Error]: {0}" -f $Url) -Plugin "New-WebRequest" `
                                        -IsDebug -Verbosity $Verbosity -WriteLog $WriteLog

                    Write-AzucarMessage -Message ("[Detailed error message]: {0}" -f $responseBody) `
                                        -Plugin "New-WebRequest" -IsDebug `
                                        -Verbosity $Verbosity -WriteLog $WriteLog
               }
            }
            Function _ConvertTo-XML{
                Param (
                    [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
                    [Object]$RawObject
                )
                Begin{
                    $StrWriter = New-Object System.IO.StringWriter
                    $DataDoc = New-Object system.xml.xmlDataDocument
                    $DataDoc.LoadXml($RawObject)
                    $Writer = New-Object system.xml.xmltextwriter($StrWriter)
                    #Indented Format
                    $Writer.Formatting = [System.xml.formatting]::Indented
                    $DataDoc.WriteContentTo($Writer)
                }
                Process{
                    #Flush Data
                    $Writer.Flush()
                    $StrWriter.flush()
                }
                End{
                    #Return data
                    return $StrWriter.ToString()
                }
            }
            Function _Convert-RAWData{
                Param (
                    [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
                    [Object]$RawObject,

                    [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
                    [String]$ContentType
                )
                Begin{
                    switch -Regex ($ContentType) { 
                        "application/(json)"
                        {
                            $RawResponse = ConvertFrom-Json -InputObject $RawObject
                        }
                        "application/(xml)"
                        {
                            $RawResponse = _ConvertTo-XML -RawObject $RawObject
                        }
                        "Default"
                        {
                            $RawResponse = $RawObject
                        }
                    }
                }
                Process{
                    #Return Object
                    Return $RawResponse
                }
                End{
                    #Nothing to do here
                }
            }
            #Method
            switch ($Method) { 
                'Connect'
                {
                    $Method = [System.Net.WebRequestMethods+Http]::Connect
                }
                'Get'
                {
                    $Method = [System.Net.WebRequestMethods+Http]::Get
                }
                'Post'
                {
                    $Method = [System.Net.WebRequestMethods+Http]::Post
                }
                'Put'
                {
                    $Method = [System.Net.WebRequestMethods+Http]::Put
                }
                'Head'
                {
                    $Method = [System.Net.WebRequestMethods+Http]::Head
                }
            }
        }
        Process{
                #Create Request
                try{
                    $request = [System.Net.WebRequest]::Create($Url)
                }
                catch{
                    _New-WebRequestException -Exception $_ -WriteLog $WriteLog -Verbosity $Verbosity
                }
                if($request -is [System.Net.HttpWebRequest]){
                    #Establish Request Method
                    $request.Method = $Method
                    #Add Headers
                    if($Headers){
                        foreach($element in $headers.GetEnumerator()){
                            $request.Headers.Add($element.key, $element.value)
                        }
                    }
                    if($Encoding){
                        #Add Accept
                        $request.Accept = $Encoding
                    }
                    #Add custom User-Agent
                    $request.UserAgent = $UserAgent
                    #Set Timeout to Infinite
                    $request.Timeout = [System.Threading.Timeout]::Infinite
                    #Create the request body if POST or PUT
                    if(($Method -eq [System.Net.WebRequestMethods+Http]::Post -or $Method -eq [System.Net.WebRequestMethods+Http]::Put) -and $Data){
                        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Data)
                        $request.ContentType = $Encoding
                        $request.ContentLength = $bytes.Length
                        [System.IO.Stream] $outputStream = [System.IO.Stream]$request.GetRequestStream()
                        $outputStream.Write($bytes,0,$bytes.Length)
                        $outputStream.Close()
                    }
                    elseif(($Method -eq [System.Net.WebRequestMethods+Http]::Post -or $Method -eq [System.Net.WebRequestMethods+Http]::Put) -and -NOT $Data){
                        $request.ContentLength = 0
                    }
                    #Lauch Request
                    try{
                        [System.Net.WebResponse] $response = $request.GetResponse() 
                        #Get the response stream
                        $rs = $response.GetResponseStream();
                        #Get Stream Reader and store into a RAW var
                        [System.IO.StreamReader] $sr = New-Object System.IO.StreamReader -argumentList $rs     
                        [String]$RAW = $sr.ReadToEnd()
                        #catch response#
                        #_New-WebResponseDetailedMessage -response $response -WriteLog $WriteLog -Verbosity $Verbosity
                    }
                    ## Catch errors from the server (404, 500, 501, etc.)
                    catch [Net.WebException]{
                        _New-WebRequestException -Exception $_ -WriteLog $WriteLog -Verbosity $Verbosity
                        <#
                        #Convert Exception
                        Convert-Exception -MyError $_ -FunctionName "New-WebRequest" -WriteLog $WriteLog
                        $ErrorRecord = New-Object System.Management.Automation.ErrorRecord(
                           (New-Object Exception("Request error in url:{0}" -f $Url)),
                           $null,
                           [System.Management.Automation.ErrorCategory]::InvalidData,
                           $null
                        )
                        #Convert Exception for URL
                        Convert-Exception -MyError $ErrorRecord -FunctionName "New-WebRequest" -WriteLog $WriteLog
                        #Get Exception Body Message
                        $reader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
                        $reader.BaseStream.Position = 0
                        $reader.DiscardBufferedData()
                        $responseBody = $reader.ReadToEnd()
                        Write-AzucarMessage -Message $responseBody -Plugin "New-WebRequest" -IsDebug -Verbosity $Verbosity -WriteLog $WriteLog
                        #>
                    }
                }
        }
        End{
            #Convert Raw Data
            $Rawobject = _Convert-RAWData -RawObject $RAW -ContentType $response.ContentType
            return $Rawobject
            #Close the response stream
            $response.Close()
        }
}

Function Get-AzSecAADLinkedObject{
    Param (
        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Object]$Authentication,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Object]$Instance,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [String]$Objectype,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [String]$ObjectId,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Switch]$GetLinks,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [String]$ObjectDisplayName,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [String]$Relationship,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [String]$APIVersion,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Bool]$WriteLog,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [System.Collections.Hashtable]$Verbosity
    )
    Begin{
        if($Authentication -eq $null){
             Write-AzucarMessage -Message $message.ConnectionAzureADErrorMessage -Plugin "Get-AzSecAADLinkedObject" `
                                 -IsDebug -Verbosity $Verbosity -WriteLog $WriteLog
             return
        }
        if($ObjectId -AND $ObjectDisplayName){
            #Write Progress information
            $statusBar=@{
                    Activity = "Azure Active Directory Analysis"
                    CurrentOperation=""
                    Status="Script started"
            }
            [String]$startCon = ("Starting Azure Rest Query on {0} to retrieve {1}" -f $ObjectDisplayName, $Relationship)
            $statusBar.Status = $startCon

            #Get Auth Header and create URI
            #$AuthHeader = $Authentication.Result.CreateAuthorizationHeader()
            $AuthHeader = ("Bearer {0}" -f $Authentication.AccessToken)
            if($GetLinks){
                $URI = '{0}/{1}/{2}/{3}/$links/{4}?api-version={5}'`
                       -f $Instance.Graph, $Authentication.TenantID, $Objectype.Trim(), $ObjectId, $Relationship, $APIVersion
            }
            else{
                $URI = '{0}/{1}/{2}/{3}/{4}?api-version={5}'`
                       -f $Instance.Graph, $Authentication.TenantID, $Objectype.Trim(), $ObjectId, $Relationship, $APIVersion
            }
        }
        else{
            $URI = $false;
        }
    }
    Process{
        try{
            if($URI){
                $requestHeader = @{
                                    "x-ms-version" = "2014-10-01";
                                    "Authorization" = $AuthHeader
                }
                ####Workaround for operation timed out ######
                #https://social.technet.microsoft.com/wiki/contents/articles/29863.powershell-rest-api-invoke-restmethod-gotcha.aspx
                $ServicePoint = [System.Net.ServicePointManager]::FindServicePoint($URI)
                Write-Progress @statusBar
                #$AllObjects = Invoke-RestMethod -Uri $URI -Headers $requestHeader -Method Get -ContentType "application/json" -TimeoutSec 60
                $AllObjects = New-WebRequest -Url $URI -Headers $requestHeader -Method Get -Encoding "application/json" `
                                             -UserAgent "Azucar" -Verbosity $Verbosity -WriteLog $WriteLog

                $ServicePoint.CloseConnectionGroup("")
                Write-AzucarMessage -Message ($message.GetRequestObjectMessage -f $ObjectDisplayName) -Plugin "Get-AzSecAADLinkedObject" `
                                         -IsDebug -Verbosity $Verbosity -WriteLog $WriteLog
                ####close all the connections made to the host####
                [void]$ServicePoint.CloseConnectionGroup("")
                $tenantObjects = @()
                $tenantObjects += $AllObjects.value
                $moreObjects = $AllObjects 
                if ($AllObjects -AND $AllObjects.'odata.nextLink'){
                    $nextLink = $AllObjects.'odata.nextLink'
                    while ($nextLink -ne $null -and $nextLink.IndexOf('token=') -gt 0){
                        $nextLink = $nextLink.Substring($nextLink.IndexOf('token=') + 6)
                        if($GetLinks){
                            $URI = '{0}/{1}/{2}/{3}/$links/{4}?api-version={5}&$top=999&$skiptoken={6}'`
                           -f $Instance.Graph, $Authentication.TenantID, $Objectype.Trim(), $ObjectId, $Relationship, $APIVersion, $nextLink
                        }
                        else{
                            $URI = '{0}/{1}/{2}/{3}/{4}?api-version={5}&$top=999&$skiptoken={6}'`
                           -f $Instance.Graph, $Authentication.TenantID, $Objectype.Trim(), $ObjectId, $Relationship, $APIVersion, $nextLink
                        }
                       ####Workaround for operation timed out ######
                       #https://social.technet.microsoft.com/wiki/contents/articles/29863.powershell-rest-api-invoke-restmethod-gotcha.aspx
                       $ServicePoint = [System.Net.ServicePointManager]::FindServicePoint($URI)
                       #$NextPage = Invoke-RestMethod -Method Get -Uri $URI -Headers $requestHeader -TimeoutSec 60
                       $NextPage = New-WebRequest -Url $URI -Method Get -Headers $requestHeader `
                                                  -Encoding "application/json" -UserAgent "Azucar" -Verbosity $Verbosity -WriteLog $WriteLog
                       ####close all the connections made to the host####
                       [void]$ServicePoint.CloseConnectionGroup("")
                       $tenantObjects += $NextPage.value
                       $nextLink = $nextPage.'odata.nextLink'
                    }
                }
            }
        }
        catch [System.Net.WebException]{
            Convert-Exception -MyError $_ -FunctionName "Get-AzSecAADLinkedObject" -WriteLog $WriteLog
            Get-AzWebRequestException -ExceptionError $_ -FunctionName "Get-AzSecAADLinkedObject" -WriteLog $WriteLog -Verbosity $Verbosity
            ####Workaround for operation timed out ######
            #https://social.technet.microsoft.com/wiki/contents/articles/29863.powershell-rest-api-invoke-restmethod-gotcha.aspx
            $ServicePoint = [System.Net.ServicePointManager]::FindServicePoint($URI)
            ####close all the connections made to the host####
            [void]$ServicePoint.CloseConnectionGroup("")
            return $null
        }
    }
    End{
        if($tenantObjects){
            Write-Progress -Activity ("Azure request for object type {0}" -f $ObjectDisplayName) -Completed -Status "Status: Completed"
            return $tenantObjects
        }
    }
}
#
Function Get-AzSecAADObject{
    Param (
        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Object]$Authentication,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Object]$Instance,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [String]$Objectype,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [String]$Query,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [String]$Method = "GET",

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Switch]$Manual,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [String]$OwnQuery,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [String]$ContentType = "application/json",

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [String]$APIVersion,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [object]$Data,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Bool]$WriteLog,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [System.Collections.Hashtable]$Verbosity
    )
    Begin{
        if($Authentication -eq $null){
             Write-AzucarMessage -Message $message.ConnectionAzureADErrorMessage -Plugin "Get-AzSecAADObject" `
                                 -IsDebug -Verbosity $Verbosity -WriteLog $WriteLog
             return
        }
        #Write Progress information
        $statusBar=@{
                Activity = "Azure Active Directory Analysis"
                CurrentOperation=""
                Status="Script started"
        }
        [String]$startCon = ("Starting Azure Rest Query on {0} to retrieve {1}" -f $Instance.Graph, $Objectype.Trim())
        $statusBar.Status = $startCon
        
        #$AuthHeader = $Authentication.Result.CreateAuthorizationHeader()
        $AuthHeader = ("Bearer {0}" -f $Authentication.AccessToken)
        if($Manual){
            $URI = $OwnQuery
        }
        elseif ($Objectype){
            $URI = '{0}/{1}/{2}?api-version={3}{4}' -f $Instance.Graph, $Authentication.TenantID, $Objectype.Trim(), $APIVersion, $Query
        }
        else{
            $URI = $false;
        }
    }
    Process{
        try{
            if($URI){
                $requestHeader = @{
                                    "x-ms-version" = "2014-10-01";
                                    "Authorization" = $AuthHeader
                }
                Write-Progress @statusBar
                ####Workaround for operation timed out ######
                #https://social.technet.microsoft.com/wiki/contents/articles/29863.powershell-rest-api-invoke-restmethod-gotcha.aspx
                $ServicePoint = [System.Net.ServicePointManager]::FindServicePoint($URI)
                switch ($Method) { 
                    'GET'
                    {
                        #$AllObjects = Invoke-RestMethod -Uri $URI -Headers $requestHeader -Method $Method -ContentType $ContentType -TimeoutSec 60
                        $AllObjects = New-WebRequest -Url $URI -Headers $requestHeader `
                                                     -Method $Method -Encoding $ContentType -UserAgent "Azucar" -Verbosity $Verbosity -WriteLog $WriteLog
                    }
                    'POST'
                    {
                        if($Data){
                            #$AllObjects = Invoke-RestMethod -Uri $URI -Headers $requestHeader -Method $Method -ContentType $ContentType -Body $Data -TimeoutSec 60
                            $AllObjects = New-WebRequest -Url $URI -Headers $requestHeader `
                                                         -Method $Method -Encoding $ContentType -Data $Data `
                                                         -UserAgent "Azucar" -Verbosity $Verbosity -WriteLog $WriteLog
                        }
                    }
                }
                Write-AzucarMessage -Message ($message.GetRequestObjectMessage -f $URI) -Plugin "Get-AzSecAADObject" `
                                    -IsDebug -Verbosity $Verbosity -WriteLog $WriteLog
                ####close all the connections made to the host####
                [void]$ServicePoint.CloseConnectionGroup("")
                $tenantObjects = @()
                $tenantObjects += $AllObjects.value
                $moreObjects = $AllObjects 
                if ($AllObjects -AND $AllObjects.'odata.nextLink'){
                    $nextLink = $AllObjects.'odata.nextLink'
                    while ($nextLink -ne $null -and $nextLink.IndexOf('token=') -gt 0){
                        $statusBar.CurrentOperation = ("Retrieving {0}" -f $Objectype.Trim())
                        $statusBar.Status = $tenantObjects.Count
                        Write-Progress @statusBar
                        $nextLink = $nextLink.Substring($nextLink.IndexOf('token=') + 6)
                        $URI = '{0}/{1}/{2}?api-version={3}&$top=999&$skiptoken={4}'`
                        -f $Instance.Graph, $Authentication.TenantID, $Objectype.Trim(), $APIVersion, $nextLink
               
                        ####Workaround for operation timed out ######
                        #https://social.technet.microsoft.com/wiki/contents/articles/29863.powershell-rest-api-invoke-restmethod-gotcha.aspx
                        $ServicePoint = [System.Net.ServicePointManager]::FindServicePoint($URI)
                        #$NextPage = Invoke-RestMethod -Method Get -Uri $URI -Headers $requestHeader -TimeoutSec 60
                        $NextPage = New-WebRequest -Method Get -Url $URI -Headers $requestHeader `
                                                   -UserAgent "Azucar" -Verbosity $Verbosity -WriteLog $WriteLog
                        ####close all the connections made to the host####
                        [void]$ServicePoint.CloseConnectionGroup("")
                        $tenantObjects += $NextPage.value
                        $nextLink = $nextPage.'odata.nextLink'
                    }
                }
            }
        }
        catch [System.Net.WebException]{
            Convert-Exception -MyError $_ -FunctionName "Get-AzSecAADObject" -WriteLog $WriteLog
            Get-AzWebRequestException -ExceptionError $_ -FunctionName "Get-AzSecAADObject" -WriteLog $WriteLog -Verbosity $Verbosity
            ####Workaround for operation timed out ######
            #https://social.technet.microsoft.com/wiki/contents/articles/29863.powershell-rest-api-invoke-restmethod-gotcha.aspx
            $ServicePoint = [System.Net.ServicePointManager]::FindServicePoint($URI)
            ####close all the connections made to the host####
            [void]$ServicePoint.CloseConnectionGroup("")
            return $null
        }
    }
    End{
        if($tenantObjects){
            Write-Progress -Activity ("Azure request for object type {0}" -f $Objectype.Trim()) -Completed -Status "Status: Completed"
            return $tenantObjects
        }
       
    }

}

Function Get-AzSecRMObject{
    Param (
        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Object]$Authentication,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Object]$Instance,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [String]$ResourceGroup,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [String]$Provider,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [String]$Objectype,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [String]$Query,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [ValidateSet("CONNECT","GET","POST","HEAD","PUT")]
        [String]$Method = "GET",

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Switch]$Manual,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [String]$ContentType = "application/json",

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [object]$Data,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [String]$OwnQuery,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [String]$APIVersion,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Bool]$WriteLog,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [System.Collections.Hashtable]$Verbosity
    )
    Begin{
        if($Authentication -eq $null){
             Write-AzucarMessage -Message $message.ConnectionAzureRMErrorMessage`
                                 -Plugin "Get-AzSecRMObject" -IsDebug -Verbosity $Verbosity -WriteLog $WriteLog
             return
        }
        #Get Authorization Header
        #$AuthHeader = $Authentication.Result.CreateAuthorizationHeader()
        $AuthHeader = ("Bearer {0}" -f $Authentication.AccessToken)
        if($Provider -and $ResourceGroup){
            $URI = '{0}/subscriptions/{1}/resourceGroups/{2}/providers/{3}/{4}?api-version={5}{6}' `
                   -f $Instance.ResourceManager, $Authentication.subscriptionId,`
                      $ResourceGroup, $Provider, $Objectype.Trim(), $APIVersion, $Query
        }
        elseif($Provider -and -NOT $ResourceGroup){
            $URI = '{0}/subscriptions/{1}/providers/{2}/{3}?api-version={4}{5}' `
                   -f $Instance.ResourceManager, $Authentication.subscriptionId,`
                      $Provider, $Objectype.Trim(), $APIVersion, $Query
        }
        elseif($Manual){
            $URI = $OwnQuery
        }
        else{
            $URI = '{0}/subscriptions/{1}/{2}?api-version={3}{4}' -f $Instance.ResourceManager, $Authentication.subscriptionId, $Objectype.Trim(), $APIVersion, $Query
        }
    }
    Process{
        if($URI){$requestHeader = @{"x-ms-version" = "2014-10-01";"Authorization" = $AuthHeader}}       
        #Perform query
        ####Workaround for operation timed out ######
        #https://social.technet.microsoft.com/wiki/contents/articles/29863.powershell-rest-api-invoke-restmethod-gotcha.aspx
        $ServicePoint = [System.Net.ServicePointManager]::FindServicePoint($URI)
        try{
            $AllObjects = @()
            switch ($Method) { 
                    'GET'
                    {
                        $Objects = New-WebRequest -Url $URI -Headers $requestHeader -Method $Method `
                                                  -Encoding "application/json" -UserAgent "Azucar" -Verbosity $Verbosity -WriteLog $WriteLog
                    }
                    'POST'
                    {
                        $Objects = New-WebRequest -Url $URI -Headers $requestHeader `
                                                     -Method $Method -Encoding $ContentType -Data $Data `
                                                     -UserAgent "Azucar" -Verbosity $Verbosity -WriteLog $WriteLog
                    }
            }
            ####close all the connections made to the host####
            [void]$ServicePoint.CloseConnectionGroup("")
            if($Objectype){
                Write-AzucarMessage -Message ($message.GetRequestObjectMessage -f $Objectype)`
                                    -Plugin "Get-AzSecRMObject" -IsDebug -Verbosity $Verbosity -WriteLog $WriteLog
            }
            else{
                Write-AzucarMessage -Message $URI -Plugin "Get-AzSecRMObject" -IsDebug -Verbosity $Verbosity -WriteLog $WriteLog
            }
            if($Objects.value){
                $AllObjects+= $Objects.value
            }
            else{
                $AllObjects+= $Objects
            }
            #Search for paging objects
            if ($Objects.'odata.nextLink'){
                $nextLink = $Objects.'odata.nextLink'
                while ($nextLink -ne $null -and $nextLink.IndexOf('token=') -gt 0){
                    $nextLink = $nextLink.Substring($nextLink.IndexOf('token=') + 6)
                    #Construct URI
                    $URI = '{0}/subscriptions/{1}/{2}?api-version={3}&$top=999&$skiptoken={4}'`
                           -f $Instance.ResourceManager, $Authentication.subscriptionId, $Objectype.Trim(), $APIVersion, $nextLink
                    ####Workaround for operation timed out ######
                    #https://social.technet.microsoft.com/wiki/contents/articles/29863.powershell-rest-api-invoke-restmethod-gotcha.aspx
                    $ServicePoint = [System.Net.ServicePointManager]::FindServicePoint($URI)
                    #Make RestAPI call
                    $NextPage = New-WebRequest -Method Get -Url $URI -Headers $requestHeader `
                                               -UserAgent "Azucar" -Verbosity $Verbosity -WriteLog $WriteLog
                    $AllObjects+= $NextPage.value
                    $nextLink = $nextPage.'odata.nextLink'
                    ####close all the connections made to the host####
                    [void]$ServicePoint.CloseConnectionGroup("")
                }
            }
        }
        catch [System.Net.WebException]{
            Convert-Exception -MyError $_ -FunctionName "Get-AzSecRMObject" -WriteLog $WriteLog
            Get-AzWebRequestException -ExceptionError $_ -FunctionName "Get-AzSecRMObject" -WriteLog $WriteLog -Verbosity $Verbosity
            ####Workaround for operation timed out ######
            #https://social.technet.microsoft.com/wiki/contents/articles/29863.powershell-rest-api-invoke-restmethod-gotcha.aspx
            $ServicePoint = [System.Net.ServicePointManager]::FindServicePoint($URI)
            ####close all the connections made to the host####
            [void]$ServicePoint.CloseConnectionGroup("")
            return $null
        }
    }
    End{
        if($AllObjects){
            return $AllObjects     
        } 
    }
}

Function Get-AzSecSMObject{
    Param (
        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Object]$Authentication,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Object]$Instance,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [String]$ObjectType,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Bool]$WriteLog,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [System.Collections.Hashtable]$Verbosity
    )
    Begin{
        if($Authentication -eq $null){
            Write-AzucarMessage -Message $message.ConnectionAzureSMErrorMessage`
                                -Plugin "Get-AzSecSMObject" -IsDebug -Verbosity $Verbosity -WriteLog $WriteLog
            return
        }
        #Write Progress information
        $statusBar=@{
                Activity = "Azure Service Management Analysis"
                CurrentOperation=""
                Status="Script started"
        }
        [String]$startCon = ("Starting Azure Service Management Rest Query on {0} to retrieve {1}" -f $Instance.ServiceManagement, $ObjectType)
        $statusBar.Status = $startCon
        #$AuthHeader = $Authentication.Result.CreateAuthorizationHeader()
        $AuthHeader = ("Bearer {0}" -f $Authentication.AccessToken)
        $URI = '{0}/{1}/services/{2}' -f $Instance.ServiceManagement, $Authentication.subscriptionId, $ObjectType
    }
    Process{
        try{
            if($URI){$requestHeader = @{"x-ms-version" = "2014-10-01";"Authorization" = $AuthHeader}}
            Write-Progress @statusBar
            ####Workaround for operation timed out ######
            #https://social.technet.microsoft.com/wiki/contents/articles/29863.powershell-rest-api-invoke-restmethod-gotcha.aspx
            $ServicePoint = [System.Net.ServicePointManager]::FindServicePoint($URI)
            #$AllObjects = Invoke-RestMethod -Uri $URI -Headers $requestHeader -Method GET -ContentType "application/json" -TimeoutSec 60
            $AllObjects = New-WebRequest -Url $URI -Headers $requestHeader -Method Get `
                                        -UserAgent "Azucar" -Verbosity $Verbosity -WriteLog $WriteLog
            ####close all the connections made to the host####
            [void]$ServicePoint.CloseConnectionGroup("")
            Write-AzucarMessage -Message ($message.GetRequestObjectMessage -f $ObjectType)`
                                -Plugin "Get-AzSecSMObject" -IsDebug -Verbosity $Verbosity -WriteLog $WriteLog
        }
        catch [System.Net.WebException]{
            Convert-Exception -MyError $_ -FunctionName "Get-AzSecSMObject" -WriteLog $WriteLog
            Get-AzWebRequestException -ExceptionError $_ -FunctionName "Get-AzSecSMObject"  -WriteLog $WriteLog -Verbosity $Verbosity
            ####Workaround for operation timed out ######
            #https://social.technet.microsoft.com/wiki/contents/articles/29863.powershell-rest-api-invoke-restmethod-gotcha.aspx
            $ServicePoint = [System.Net.ServicePointManager]::FindServicePoint($URI)
            ####close all the connections made to the host####
            [void]$ServicePoint.CloseConnectionGroup("")
            return $null

        }
    }
    End{
        if($AllObjects){
            Write-Progress -Activity ("Azure request for object type {0}" -f $Objectype.Trim()) -Completed -Status "Status: Completed"
            return $AllObjects
        }
       
    }

}

