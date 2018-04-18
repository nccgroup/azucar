Function New-Report{
    Param (
        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [String]$Path,

        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [String]$TenantID

    )
    Begin{
        $target = "$Path\Reports"
        if (!(Test-Path -Path $target)){
            $tmpdir = New-Item -ItemType Directory -Path $target
            Write-Verbose "Folder Reports created in $target...." @VerboseOptions
        }
        $folder = "$target\" + ([System.Guid]::NewGuid()).ToString() + $TenantID
    }
    Process{
        if (!(Test-Path -Path $folder)){
            try{
				$tmpdir = New-Item -ItemType Directory -Path $folder
				return $folder
			}
			catch{
			    Write-Verbose "Failed to create new directory. Trying to generate new guid...." @VerboseOptions
			    New-Report -Path $Path -TenantID $TenantID
			}
        }
    }
    End{
        #Nothing to do here
    }
}


