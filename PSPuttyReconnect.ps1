[CmdletBinding(DefaultParameterSetName='Base64 Credentials')]
[OutputType('System.Management.Automation.PSObject')]
Param
(
    [switch]
    $SkipUserSetup = $True
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

    Param (

        $User = $env:USERNAME

    )

    if(($User).IndexOf('.') -gt 0) {
        $script:UserName = $(($($User).Split('.')[0])[0]) + $($User).Split('.')[-1]
    }
    else {
        $script:UserName = $User    
    }
    $Username
}

Function Get-DnsTxt
{

    if($SkipUserSetup) { return }

    if(-not (Get-Command -Name Resolve-DnsName -ErrorAction SilentlyContinue)) {

        # attempting old school method
        $txtEntry = Get-DnsTxtNslookup
        if($txtEntry -lt 10) {
            # Write-Host "Sorry you are running an old version of Windows and we could not use an alternate method to lookup TXT record, cannot continue" -ForegroundColor Red
            # exit 1
            $txtEntry = "ZGVtb3Jlc3R1c2VyOlczbGxEb25lWW91Rm91bmQxdDotKQ=="
            return $txtEntry
        }
        else {
            return $txtEntry  
        }
    }

    try {
        $txtEntry = Resolve-DnsName -Name demorest.cloud-msp.net -Type TXT -ErrorAction Stop
        $txtEntry.Strings
    }
    catch {
        Write-Error "Failed to get DNS TXT record"
    }

    if(-not($txtEntry.Strings)) {
        $txtEntry = "ZGVtb3Jlc3R1c2VyOlczbGxEb25lWW91Rm91bmQxdDotKQ=="
        return $txtEntry            
    }
}

function Get-DnsTxtNslookup
{
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = "$env:SystemRoot\System32\nslookup.exe"
    $pinfo.RedirectStandardError = $true
    $pinfo.RedirectStandardOutput = $true
    $pinfo.UseShellExecute = $false
    $pinfo.Arguments = "-querytype=TXT -timeout=10 demorest.cloud-msp.net"
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $pinfo
    $p.Start() | Out-Null
    $p.WaitForExit()
    $stdout = $p.StandardOutput.ReadToEnd()
    $stderr = $p.StandardError.ReadToEnd()

    if($stdout -match "demorest.cloud-msp.net") {
        $stdout|%{$_.split('"')[1]}
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
        'Uri' = 'http://ansible.cloud-msp.net/api/v2/job_templates/6/launch/'
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
        exit 1
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

function Get-PSScript
{
    Param(

        $Url = 'https://raw.githubusercontent.com/tonyskidmore/PSPuttySession/master/PSPuttySession.ps1'
    )

    $outputFile = "$tmpDir\PSPuttySession.ps1"


    try {
        if(-not (Test-Path -Path $outputFile)) {
            Invoke-WebRequest -Uri $Url -OutFile $outputFile -ErrorAction Stop
        }
    }
    catch {
        Write-Error -Message "Failed to download PS script"
    }

}

function Set-HostKey
{

    $HostKey = '0x10001,0xe127dd89afacb7f4dc6a1e3193b07f66e6f1ee4fa840cf2c7921d3f7b50283f72cf0e464232483b0869440c27458fdbbb4e87449de53d3cf2fd000ef2a7d329c325972885d5dd5aef0f7cf15fe897d6d98af1a31d76933c061e15962df081804a20165fe4b8ea9360d0a3466e4dcd3d75dc4e5519209e00b817a436ccdeac150321d04a9cef64a10d8117217d6f2f956a9d49b19e508511a7af87ba35bfe4d8ebcb06074ef57050dc8337dcca805923a72a74fbc21a90301db8d7b3bf939c99d63c2d7e2bf69e192f3619a328a76a36e78132b3ba219ca4ca7f532159a11344cb60b5bccca08c3380ed39c3dabf7a4044f700eddad5683dd93cfa57f744d16d3'

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
        $HostKey = '2b:8a:67:2e:0e:a3:a3:39:d7:da:0b:2f:6a:c6:fb:ab'
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
Get-PSScript
$setKey = Set-HostKey
if(Get-Key -and $setKey) { 
    Write-Output "Your username is: $UserName"    
    Invoke-PuttySession 
}

