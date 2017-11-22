[CmdletBinding(DefaultParameterSetName='Base64 Credentials')]
[OutputType('System.Management.Automation.PSObject')]
Param
(
    [switch]
    $SkipUserSetup
)

#region functions

Function ConvertFrom-Base64
{
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True, Position=0, ValueFromPipeline=$True)]
        [string]
        $InputObject
    )
    
    if($SkipUserSetup) { return }

    try {
        [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($InputObject))
    }
    catch {
        Write-Error "Failed to decode string"
    }

}

function Get-UserName
{
    if(($env:USERNAME).IndexOf('.')) {
        $script:UserName = $(($($env:USERNAME).Split('.')[0])[0]) + $($env:USERNAME).Split('.')[1]
    }
    else {
        $script:UserName = $env:USERNAME    
    }
}

Function Get-DnsTxt
{

    if($SkipUserSetup) { return }

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

    if($SkipUserSetup) { return }

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

    if($SkipUserSetup) { return }

    $random = Get-Random -Minimum 1 -Maximum 30

    for($i = 1 ; $i -lt $random ; $i++) {
        Write-Progress -Activity "Throttling mechnism" -PercentComplete ($i/$random*100)    
        Start-Sleep -Seconds 1
    }
}

function Start-AwxTemplate
{

    if($SkipUserSetup) { return }

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

function Get-Putty
{
    Param(

        $Url = 'https://the.earth.li/~sgtatham/putty/latest/w32/putty.exe'
    )

    $outputFile = "$tmpDir\putty.exe"


    #try {
        Invoke-WebRequest -Uri $Url -OutFile $outputFile -ErrorAction Stop
    #}
    #catch {
    #    Write-Error -Message "Failed to download putty"
    #}

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

# main script execution
Get-DnsTxt | ConvertFrom-Base64 | ConvertTo-PSCredential
Get-UserName
Wait-Random
Start-AwxTemplate
New-ProjectSpace
Get-Putty


Write-Output "Your username is: $UserName"