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
    if(($env:USERNAME).IndexOf('.') -gt 0) {
        $script:UserName = $(($($env:USERNAME).Split('.')[0])[0]) + $($env:USERNAME).Split('.')[1]
    }
    else {
        $script:UserName = $env:USERNAME    
    }
}

Function Get-DnsTxt
{

    if($SkipUserSetup) { return }

    if(-not (Get-Command -Name Resolve-DnsName -ErrorAction SilentlyContinue)) {

        Write-Output "Sorry you are running an OLD unsupported version on Windows, cannot continue"
        exit
    }

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
        Write-Progress -Activity "Throttling mechanism" -PercentComplete ($i/$random*100)    
        Start-Sleep -Seconds 1
    }

    Write-Progress -Activity "Throttling mechanism" -Completed
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


    try {
        if(-not (Test-Path -Path $outputFile)) {
            Invoke-WebRequest -Uri $Url -OutFile $outputFile -ErrorAction Stop
        }
    }
    catch {
        Write-Error -Message "Failed to download putty"
    }

}

function Set-HostKey
{

    $HostKey = '0x10001,0xb5c2a1b057775cc1336dcd8edc08a60d3648970c39b489f904a02352abd617332815d6f94cc9017209c26345a133379d4c9a8552d34c6d4a1d6539a8d5d015068868e19c28e215243de5587383b8dca8a270942dcb781ab05542e6f7e7d80f63fbf3a0390aa8dba6dac230c74682d475dfb97a9bea085e6f406cce64
eeb0baab350dd252563e8b609baf6c465a8f9d3c74af745a3567ac835c19b548f0d409910029bda89e16ade19869bd043271daf1532160c5088b8bb3b6c4eb77f766bd42c2e2299794edad1b17cf8eee9d8e152321ff75f99c1715d061361cf4a919eddfe38416e9aa577afde28d9d9eb42aa0d117e6ef9fa8e9665932c643f3ba
ac0971'

    $regName = 'rsa2@22:jumphost.cloud-msp.net'

    try {
        if(-not (Test-Path -Path HKCU:\software\SimonTatham\PuTTY\SshHostKeys -ErrorAction Stop)) {
            $puttyRoot = New-Item -Path HKCU:\software\SimonTatham\
            $puttyReg = New-Item -Path HKCU:\software\SimonTatham\PuTTY
            $puttySshHostKey = New-Item -Path HKCU:\software\SimonTatham\PuTTY -Name SshHostKeys -ErrorAction Stop
        }
    }
    catch {
        Write-Error -Message "Failed create putty registry key"
        return $false    
    }

    try {
        $newProperty = New-ItemProperty -Path "HKCU:\software\SimonTatham\PuTTY\SshHostKeys" -Name $regName -Value $HostKey -PropertyType String -Force -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Error -Message "Failed to set hostkey"
        return $false
    }
    
    return $true
}

function Get-Key
{
    Param(

        $Url = "http://jumphost.cloud-msp.net/$UserName.ppk"

    )

    $outputFile = "$tmpDir\$UserName.ppk"
    $retries = 20
    $sleepSeconds = 10

    for($i = 1 ; $i -lt $retries ; $i++) {
        Write-Progress -Activity "Attempting to acquire the key" -PercentComplete ($i/$retries*100)

        if(Test-Path -Path $outputFile) {
            $keyFound = $true
            Write-Progress -Activity "Attempting to acquire the key" -Completed
            break
        }
        else {
            try {
                Invoke-WebRequest -Uri $Url -OutFile $outputFile -ErrorAction SilentlyContinue
            }
            catch {

            }
            if(Test-Path -Path $outputFile) {
                $keyFound = $true
                Write-Progress -Activity "Attempting to acquire the key" -Completed
                break
            }
            else {
                Write-Progress -Activity "Attempting to acquire the key" -PercentComplete ($i/$retries*100) -Status "$i of $retries attempts" -CurrentOperation "Sleeping $sleepSeconds seconds"
                Start-Sleep -Seconds $sleepSeconds
            }
        }
    }

    if(-not $keyFound) { 
        Write-Progress -Activity "Failed to acquire the key" -Completed
        Write-Error "Unable to obtain the key"
        return $false
    } else {
        Write-Output "Key obtained"
        return $true
    }


}

function Invoke-PuttySession
{
    Param(

        [string]
        $Hostname = 'jumphost.cloud-msp.net',

        [string]
        $User = $UserName,

        [string]
        $PrivateKey = (Join-Path -Path $tmpDir -ChildPath "$UserName.ppk"),

        [string]
        $HostKey = '3d:de:ea:73:7b:d4:43:8f:d1:f5:41:c4:ca:b0:39:a7'
    )

    try {
        $puttyPath = Join-Path -Path $tmpDir -ChildPath 'putty.exe'
        $argumentList = "$User@$Hostname -i $PrivateKey -hostkey $HostKey"

        $result = Start-Process -FilePath $puttyPath -ArgumentList $argumentList -NoNewWindow -ErrorAction Stop
    }
    catch {
        Write-Error -Message "Failed to run putty session"
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

# main script execution
Get-DnsTxt | ConvertFrom-Base64 | ConvertTo-PSCredential
Get-UserName
Wait-Random
Start-AwxTemplate
New-ProjectSpace
Get-Putty
$setKey = Set-HostKey
if(Get-Key -and $setKey) { 
    Write-Output "Your username is: $UserName"    
    Invoke-PuttySession 
}

