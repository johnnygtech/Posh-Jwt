<#

Implementation of JSON Web Tokens Written in Powershell
John Allen Gleason
Fall 2017

#>
function ConvertTo-Base64
{
    <#
    .SYNOPSIS
    Short description

    .DESCRIPTION
    Long description
    
    .PARAMETER text
    Parameter description
    
    .EXAMPLE
    An example
    
    .NOTES
    General notes
    #>
    Param(
        [parameter()][string]$text,
        [parameter()][switch]$noEncoding
    );    
    #https://adsecurity.org/?p=478
    Write-Verbose "Entering ConvertTo-Base64"
    Write-Verbose "Encoding $text as UTF8 ByteArray"
    if($noEncoding)
    {
        return [Convert]::ToBase64String($text)
    }
    else
    {
        $Bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)

        Write-Verbose "Converting ByteArray to Base64 string"    
        $EncodedText =[Convert]::ToBase64String($Bytes)

        Write-Verbose "Returning Encoded Text`r`nLeaving ConvertTo-Base64"
        return $EncodedText 
    }
}

function ConvertFrom-Base64
{
    <#
    .SYNOPSIS
    Short description
    
    .DESCRIPTION
    Long description
    
    .PARAMETER base64EncodedText
    Parameter description

    .PARAMETER noEncoding
    Don't use UTF8 Encoding.
    Used for things like, cryptographic signatures
    
    .EXAMPLE
    An example
    
    .NOTES
    General notes
    #>
    Param(
        [parameter()][string]$base64EncodedText,
        [parameter()][switch]$noEncoding
    );
    #https://adsecurity.org/?p=478
    Write-Verbose "Entering ConvertFrom-Base64"
    Write-Verbose "Converting from Base64 string`r`nGetting UTF8 Encoded String`r`nReturning data`r`nLeaving ConvertFrom-Base64"
    if($noEncoding)
    {
        return [System.Convert]::FromBase64String($base64EncodedText)
    }
    else
    {
        return [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($base64EncodedText))
    }
}

function ConvertTo-URLEncodedString
{
    <#
    .SYNOPSIS
    Short description
    
    .DESCRIPTION
    Long description
    
    .PARAMETER text
    Parameter description
    
    .EXAMPLE
    An example
    
    .NOTES
    General notes
    #>
    Param(
        [parameter()][string]$text
    );
    #https://gallery.technet.microsoft.com/scriptcenter/Encoding-and-Decoding-URL-99dc4256
    Write-Verbose "Entering ConvertTo-URLEncodedString"
    Write-Verbose "Calling system.web.httputility, urlencode on passed in text"
    $Encode = [System.Web.HttpUtility]::UrlEncode($text)

    Write-Verbose "Returning Encoded Text"
    Write-Verbose "Leaving ConvertTo-UrlEncodedString"
    return $Encode
}
function ConvertFrom-URLEncodedString
{
    <#
    .SYNOPSIS
    Short description
    
    .DESCRIPTION
    Long description
    
    .PARAMETER EncodedData
    Parameter description
    
    .EXAMPLE
    An example
    
    .NOTES
    General notes
    #>
    Param(
        [parameter()][string]$EncodedData
    );
    #https://gallery.technet.microsoft.com/scriptcenter/Encoding-and-Decoding-URL-99dc4256
    Write-Verbose "Entering ConvertFrom-URLEncodedString"
    Write-Verbose "Calling System.Web.HttpUtility, UrlDecode"
    $Decode = [System.Web.HttpUtility]::UrlDecode($EncodedData)

    Write-Verbose "Returning decoded data"
    Write-Verbose "Leaving ConvertFrom-URLEncodedString" 
    return $Decode
}
function New-MessageSignature
{
    <#
    .SYNOPSIS
    Short description
    
    .DESCRIPTION
    Long description
    
    .PARAMETER message
    Parameter description
    
    .PARAMETER algorithm
    Parameter description
    
    .PARAMETER secret
    Parameter description
    
    .PARAMETER thumbprint
    Parameter description
    
    .EXAMPLE
    An example
    
    .NOTES
    General notes
    #>
    Param(
        [parameter(Position=0)][string]$message,
        [parameter(Position=1)][string][validateSet("HS256","CERT")]$algorithm,
        [parameter(Position=2,ParameterSetName="HS256")][string]$secret,
        [parameter(Position=3,ParameterSetName="CERT")][string]$thumbprint
    )
    Write-Verbose "Entering New-MessageSignature"
    Write-Verbose "Switching on specified algorithm"
    switch($algorithm)
    {
        "HS256"
        {
            Write-Verbose "Algorithm HS256"
            #https://gist.github.com/jokecamp/2c1a67b8f277797ecdb3
            $hmacsha = New-Object System.Security.Cryptography.HMACSHA256
            $hmacsha.key = [Text.Encoding]::UTF8.GetBytes($secret)
            $signature = $hmacsha.ComputeHash([Text.Encoding]::UTF8.GetBytes($message))
            $signature = [convert]::ToBase64String($signature)
        }
        "CERT"
        {
            Write-Verbose "Algorithm CERT"
            #TODO: loop over all matching thumprints and choose one with a private key...
            #Find Cert By Thumprint
            Write-Verbose "Finding cert that matches thumprint"

            $cert = Get-ChildItem Cert:\ -Recurse | Where-Object { $_.Thumbprint -eq $thumbprint }
            Write-Verbose "Choosing cert at index 1"
            Write-Verbose "$Cert"
            $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cert[1])
            #test private key
            Write-verbose "Testing chosen certificates private key"
            if(!$certificate.HasPrivateKey)
            {
                Write-error "Certificate specified by thumprint $thumbprint does not have a valid private key"
                break;
            }

            Write-Verbose "Encoding message as utf8 byte array"
            $dataBytes = [Text.Encoding]::UTF8.GetBytes($message)

            #TODO: Implement other algorithms!
            Write-Verbose "new SHA1Managed Algorith"
            $algo = new-object System.Security.Cryptography.SHA1Managed;
            Write-Verbose "Leveragin Certificate privatekey, signdata method to create signature byte array"
            $sigBytes = $certificate.PrivateKey.SignData($dataBytes,$algo)
            Write-verbose "Converting signature byte array to base65 string"
            $signature = [convert]::ToBase64String($sigBytes)
        }
        default {Write-Error "Algorithm not implemented: $algorith`r`nTry HS256"}
    }
    Write-Verbose "Returning signature string"
    Write-verbose "Leaving New-MessageSignature"
    return $signature
}

function Test-MessageSignature
{
    Param(
        [parameter(Position=0)][string]$message,
        [parameter(Position=1)][string]$signature,
        [parameter(Position=2)][string][validateSet("HS256","CERT")]$algorithm,
        [parameter(Position=3,ParameterSetName="HS256")][string]$secret,
        [parameter(Position=4,ParameterSetName="CERT")][string]$thumbprint
    )
    switch($algorithm)
    {
        "HS256"
        {
            Write-Verbose "Algorithm HS256"
            #https://gist.github.com/jokecamp/2c1a67b8f277797ecdb3
            Write-Verbose "creating new instance of system.Security.Cryptography.HMACSHA25"
            $hmacsha = New-Object System.Security.Cryptography.HMACSHA256
            
            Write-Verbose "Getting UTF8 Encoded Bytes of the secret, setting as key on hmacsha256 object"
            $hmacsha.key = [Text.Encoding]::UTF8.GetBytes($secret)
            
            Write-Verbose "Encoding message, then computing hash of message"
            $newSigBytes = $hmacsha.ComputeHash([Text.Encoding]::UTF8.GetBytes($message))
            
            Write-Verbose "Converting signature to Base64 string"
            $NewSig = [Convert]::ToBase64String($newSigBytes)
        }
        "CERT"
        {
            Write-Verbose "Algorithm CERT"
            #TODO: loop over all matching thumprints and choose one with a private key...
            #Find Cert By Thumprint
            Write-Verbose "Finding Certificate by thumprint"
            $cert = Get-ChildItem Cert:\ -Recurse | Where-Object { $_.Thumbprint -eq $thumbprint }
            Write-verbose "$cert"
            Write-Verbose "Choosing certificate at index 1"
            $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cert[1])

            Write-Verbose "Generating utf8 encoded message byte array"
            $dataBytes = [Text.Encoding]::UTF8.GetBytes($message)
            Write-verbose "Generating utf8 encoded Signature byte array"
            $signatureBytes = [convert]::FromBase64String($signature)
            #TODO: Implement other algorithms!
            Write-Verbose "Creating new system.security.cryptography.Sha1Managed object"
            $algo = new-object System.Security.Cryptography.SHA1Managed;

            $verified = $certificate.PublicKey.Key.VerifyData($dataBytes,$algo,$signatureBytes)
            return $verified
            #$sigBytes = $certificate.PrivateKey.SignData($dataBytes,$algo)
            #$signature = [convert]::ToBase64String($sigBytes)
        }
        default {Write-Error "Algorithm: $algorithm not implemented"; break;}
    }
    return $($newSig -eq $signature)
}

<#
function Test-MessageSignature
{
    Param(
        [parameter()]$signedmessage,
        [parameter()]$signature,
        [parameter()]$secret,
        [parameter()][switch]$base64
    );
    if($base64)
    {
        $signedMessageSplit = $(ConvertFrom-Base64 $signedmessage).split(".")
    }
    else
    {
        $signedmessageSplit = $signedmessage.split(".")    
    }
    $count = $signedMessageSplit.Count
    if($count -ne 2)
    {
        Write-Warning "Invalid JWT, wrong number of components"
        return $false
    }
    $decodedMessagedAlg = $(ConvertFrom-Json $signedMessageSplit[0]).alg
    switch($decodedMessagedAlg)
    {
        "HS256"
        {
            $newSig = Sign-Message -message $($signedmessage -join ".") -algorithm HS256 -secret $secret
            if($newSig -eq $signedMessage[2])
            {
                return $true
            }
        }
        default {Write-Error "Algorithm not implemented: $algorith`r`nTry HS256"}
        
    }
    return $false
}
#>

function New-JwtHeader
{
    param(
        [parameter()][validateset("HS256","CERT")]$algorithm,
        [parameter(ParameterSetName="CERT")]$thumbprint
    );
    switch($algorithm)
    {
        "HS256"
        {
            $headerTemplate = @{
                "alg"="HS256";
                "typ"="JWT"
            }
        }
        "CERT"
        {
            if(!$thumbprint)
            {
                Write-Error "No certificate thumprint identified`r`nAlso note, certificate must be available within computers certificate store"
                break
            }
            #TODO: if Cert, specify thumprint
            ##The idea here is to identify the certificate thumbprint used for signing
            ##Should it be Issuer?  or its own thing? thumprint/tpr?  hmmm
            $headerTemplate = @{
                "alg"="CERT";
                "typ"="JWT";
                "iss"=$thumbprint;
                "tpr"=$thumbprint;
            }
        }
        default{Write-error "Algorithm Not Implemented"}
    }

    return $headerTemplate
}

function New-JwtPayload
{
    $payloadTemplate = @{
        "iss"= "00000000-0000-0000-0000-000000000000"
        "sub"= "1234567890";
        "name"= "John Doe";
        "admin"= $true;
        "moreRandomData"="here is where I put a message"
        "exp"= $($(Get-Date).AddDays(1)).ToString()
        "nbf" = $($(Get-Date)).ToString()
        "iat" = $($(Get-Date)).ToString()
        "jti" = "11111111-1111-1111-1111-111111111111"
      }

    return $payloadTemplate
}

function New-Jwt
{
    param(
        [parameter()]$header,
        [parameter()]$payload,
        [parameter()]$secret = "secret",
        [parameter()][switch]$EncodeSignature
    );
    $bHeader = $(ConvertTo-Base64 $(ConvertTo-Json $header))
    $bPayload = $(ConvertTo-Base64 $(ConvertTo-Json $payload))
    $bClaim = $bHeader + "." + $bPayload
    switch($($header.alg))
    {
        "HS256"
        {
            $signature = New-MessageSignature -message $bClaim -algorithm $($header.alg) -secret $secret
        }
        "CERT"
        {
            $signature = New-MessageSignature -message $bClaim -algorithm $($header.alg) -thumbprint $($header.tpr)
        }
    }
    
    if($EncodeSignature)
    {
        $signature = [Convert]::ToBase64String($signature)
    }

    $claim = $bClaim + "." + $signature
    $claim
}

function Test-Jwt
{
    param(
        [parameter()]$token,
        [parameter()]$secret,
        [parameter()][switch]$EncodedSignature
    );
    <#
    first split the claim into its parts
    #>
    $split = $token.split(".")
    $encodedheader = $split[0]
    $encodedpayload = $split[1]
    $rawSignature = $split[2]

    #next decode relavent items
    $header = ConvertFrom-Base64 $encodedheader
    $payload = ConvertFrom-Base64 $encodedpayload

    if($EncodedSignature)
    {
        $signature = [Convert]::FromBase64String($rawSignature)
    }
    else
    {
        $signature = $rawSignature
    }

    #reassemble the header and payload
    $dataToTest = "$encodedHeader.$encodedPayload"
    $headerObj = $(ConvertFrom-Json $header)
    #generate new signature
    switch($headerObj.alg)
    {
        "HS256"
        {
            $signatureisValid = Test-MessageSignature -message $dataToTest -signature $signature -algorithm $headerObj.alg -secret $secret
        }
        "CERT"
        {
            $signatureIsValid = Test-MessageSignature -message $dataToTest -signature $signature -algorithm $headerObj.alg -thumbprint $headerObj.tpr
        }
    }
    #compare new signature and original, validating secret

    if(!$signatureisValid)
    {
        Write-Error "Invalid Signature"
    }
    #Now verify age and validity options
    $nbf = $payload.nbf
    if($nbf)
    {
        if((Get-Date) -lt $nbf)
        {
            Write-Error "JWT not yet valid, wait until $nbf"
            $notYetValid = $true
        }
    }

    $exp = $payload.exp
    if($exp)
    {
        if((Get-Date) -gt $exp)
        {
            Write-Error "JWT has expired"
            $expired = $true
        }
    }
    if(!$expired -and !$notYetValid -and $signatureisValid)
    {
        return $true
    }
    return $false
}

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
