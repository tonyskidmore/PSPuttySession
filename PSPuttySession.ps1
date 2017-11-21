#region functions

Function ConvertFrom-Base64
{
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True, Position=0, ValueFromPipeline=$True)]
        [string]
        $InputObject
    )
    
    try {
        [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($InputObject))
    }
    catch {
        Write-Error "Failed to decode string"
    }

}

function Get-UserName
{

  $script:UserName = $(($($env:USERNAME).Split('.')[0])[0]) + $($env:USERNAME).Split('.')[1]

}

Function Get-DnsTxt
{
    try {
        $txtEntry = Resolve-DnsName -Name demorest.cloud-msp.net -Type TXT -ErrorAction Stop
        $txtEntry.Strings
    }
    catch {
        Write-Error "Failed to get DNS TXT record"
    }
}

Function ConvertTo-PSCredential {
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCredential])]      
    Param(

        [Parameter(Mandatory=$True, Position=0, ValueFromPipeline=$True)]
        [string]
        $InputObject
    )

    $u = $InputObject.split(':',2)[0]
    $p = $InputObject.split(':',2)[1]

    try {
        if($u -and $p) {
            $ps = ConvertTo-SecureString -AsPlainText -Force -String $p -ErrorAction Stop
            $credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $u, $ps -ErrorAction Stop
            if($credential -is [System.Management.Automation.PSCredential]) {
                $script:cred = $credential
            } else {
                Write-Error -Message "Failed to process base64 string"
            }            
        }
        else {
            Write-Error -Message "Failed to process base64 string"
        }
    }
    catch {
        Write-Error -Message "Failed to process base64 string"
    }
}

function Wait-Random {

    $random = Get-Random -Minimum 1 -Maximum 30

    for($i = 1 ; $i -lt $random ; $i++) {
        Write-Progress -Activity "Throttling mechnism" -PercentComplete ($i/$random*100)    
        Start-Sleep -Seconds 1
    }
}

function Start-AwxTemplate
{

    $hashData = @{
        demo_user = $UserName
    }

    $extraVars = @{
        extra_vars = $hashData
    }

    $params = @{
        'Uri' = 'http://awxdemo.cloud-msp.net/api/v2/job_templates/7/launch/'
        'Credential' = $cred
        'Method' = 'Post'
        'ContentType' = 'application/json'
        'ErrorAction' = 'Stop'
        'Body' = ($extraVars | ConvertTo-Json)
    }
    
    try {
        $result = Invoke-RestMethod @params
        Write-Output "AWX job id: $($result.id), status = $($result.result_stdout)"
    }
    catch {
        Write-Error -Message "Failed to invoke AWX job"  
    }

}

function New-ProjectSpace
{
    $workingDir = 'PSPuttySession'
    $temp = $env:TEMP
    $script:tmpDir = Join-Path -Path $temp -ChildPath $workingDir

    if(-not (Test-Path -Path $tmpDir)) {
        try {
            $newDir = New-Item -ItemType Directory -Force -Path $tmpDir -ErrorAction Stop
        }
        catch {
            Write-Error -Message "Failed to create working directory"  
        }
    }
}


#endregion functions

Get-DnsTxt | ConvertFrom-Base64 | ConvertTo-PSCredential
Get-UserName
Wait-Random
Start-AwxTemplate
Write-Output "Your username is: $UserName"