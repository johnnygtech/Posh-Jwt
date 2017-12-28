<#

Implementation of JSON Web Tokens Written in Powershell
John Allen Gleason
Fall 2017

#>

$claimTemplate = @{
    "sub"= "1234567890";
    "name"= "John Doe";
    "admin"= $true;
    "moreRandomData"="here is where I put a message"
  }

$headerTemplate = @{
        "alg"="HS256";
        "typ"="JWT"
    }

$headerString = @"
{
    "alg": "HS256",
    "typ": "JWT"
}
"@

function ConvertTo-Base64
{
    Param(
        [parameter()][string]$text
    );
    #https://adsecurity.org/?p=478
    $Bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    $EncodedText =[Convert]::ToBase64String($Bytes)
    $EncodedText
}

function ConvertFrom-Base64
{
    Param(
        [parameter()][string]$base64EncodedText
    );
    #https://adsecurity.org/?p=478
    [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($base64EncodedText))
    $DecodedText
}

function ConvertTo-URLEncodedString
{
    Param(
        [parameter()][string]$text
    );
    #https://gallery.technet.microsoft.com/scriptcenter/Encoding-and-Decoding-URL-99dc4256
    $Encode = [System.Web.HttpUtility]::UrlEncode($text)
    return $Encode
}

function ConvertFrom-URLEncodedString
{
    #https://gallery.technet.microsoft.com/scriptcenter/Encoding-and-Decoding-URL-99dc4256
    $Decode = [System.Web.HttpUtility]::UrlDecode($Encode) 
    return $Decode
}
function Sign-Message
{
    Param(
        [parameter(Position=0)][string]$message,
        [parameter(Position=1)][string][validateSet("HS256")]$algorithm,
        [parameter(Position=2)][string]$secret
    )
    switch($algorithm)
    {
        "HS256"{
            #https://gist.github.com/jokecamp/2c1a67b8f277797ecdb3
            $hmacsha = New-Object System.Security.Cryptography.HMACSHA256
            $hmacsha.key = [Text.Encoding]::ASCII.GetBytes($secret)
            $signature = $hmacsha.ComputeHash([Text.Encoding]::ASCII.GetBytes($message))
            $signature = [Convert]::ToBase64String($signature)
        }
        default {Write-Error "Algorithm not implemented: $algorith`r`nTry HS256"}
    }
    return $signature
}

function Verify-Message
{
    Param(
        [parameter()]$signedmessage,
        [parameter()]$signature
    );
    $decodedMessagedAlg = $(ConvertFrom-Base64 $signedmessage.split("."))[0].alg
    switch($decodedMessagedAlg)
    {
        "HS256"
        {
            #TODO: protect secret... don't hard code it... get it from a trusted source
            $newSig = Sign-Message -message $signedmessage -algorithm HS256 -secret "secret"
            if($newSig -eq $signature)
            {
                return $true
            }
        }
    }
    return $false
}

function New-Header
{
    throw "not implemeneted"
}

function Get-Claim
{
    param(
        [parameter()]$header,
        [parameter()]$payload,
        [parameter()]$secret = "secret"
    );
    $bHeader = $(ConvertTo-Base64 $(ConvertTo-Json $header))
    $bPayload = $(ConvertTo-Base64 $(ConvertTo-Json $payload))
    $bClaim = $bHeader + "." + $bPayload
    $signature = Sign-Message -message $bClaim -algorithm $($header.alg) -secret $secret

    $claim = $bClaim + "." + $signature
    $claim
}
<#
$claim = Get-Claim $headerTemplate $claimTemplate
$claim
#>

function Read-Claim
{
    param(
        [parameter()]$claim
    )
    $split = $claim -split "."
    if($split.Count -ne 3)
    {
        Write-Error "Improperly Formatted Claim"
        return
    }
}
