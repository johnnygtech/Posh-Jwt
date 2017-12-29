. .\functions.ps1

<#
if you need a certificate to test with use
. .\selfsignedcert.ps1
$cert= New-SelfsignedCertificateEx -Subject "CN=JWT TEST SIGNING CERT" -EKU "Code Signing" -KeySpec "Signature" -KeyUsage "DigitalSignature" -FriendlyName "JWT TEST SIGNING CERT" -NotAfter $([datetime]::now.AddYears(5))
$cert.Thumbprint
#>

<#test claim#>
$certThumbprint = "21E76A67FC52C66384CCB5C91B301FF42948E7CA"
$secret = "secreta"

$header = New-JwtHeader -algorithm HS256
$payload = New-JwtPayload

$jwt = New-Jwt -header $header -payload $payload -secret $secret
$jwt
Test-Jwt -token $jwt -secret $secret

$certHeaders = New-JwtHeader -algorithm CERT -thumbprint $certThumbprint
$certJwt = New-jwt -header $certHeaders -payload $payload
$certJwt
Test-Jwt -token $certJwt

$message = "the quick brown fox jumps over the lazy dog"
$sig = New-MessageSignature -message $message -algorithm CERT -thumbprint $certThumbprint
Test-MessageSignature -message $message -algorithm CERT -thumbprint $certThumbprint -signature $sig

$newSig = New-MessageSignature -message $message -algorithm HS256 -secret $secret
Test-MessageSignature -message $message -signature $newSig -algorithm HS256 -secret $secret

$badPayload = New-JwtPayload
$badPayload.exp = $(Get-Date).AddDays(-2)
$expiredPayload = $badPayload

$expiredToken = New-Jwt -header $header -payload $expiredPayload -secret secret
$expiredPayload
Test-Jwt -token $expiredToken -secret secret -Verbose

$earlyPayload = New-JwtPayload
$earlyPayload.nbf = $(Get-Date).AddHours(1)
$earlyToken = New-Jwt -header $header -payload $earlyPayload -secret secret
$earlyPayload
Test-Jwt -token $earlyToken -secret secret

<#Debugging issue with signature data loss.... basically, don't encode it:
https://haacked.com/archive/2012/01/30/hazards-of-converting-binary-data-to-a-string.aspx/
$certThumbprint = "21E76A67FC52C66384CCB5C91B301FF42948E7CA"
$message = "the quick brown fox jumps over the lazy dog"
$cert = Get-ChildItem Cert:\ -Recurse | Where-Object { $_.Thumbprint -eq $certThumbprint }
$certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cert[1])
if(!$certificate.HasPrivateKey)
{
    Write-error "Certificate specified by thumprint $thumbprint does not have a valid private key"
}
$dataBytes = [Text.Encoding]::UTF8.GetBytes($message)
$algo = new-object System.Security.Cryptography.SHA1Managed;
$sigBytes = $certificate.PrivateKey.SignData($dataBytes,$algo)
$signature = [convert]::ToBase64String($sigBytes)
$signature

$publicCerts = Get-ChildItem Cert:\ -Recurse | Where-Object { $_.Thumbprint -eq $certThumbprint }
$blahCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($publicCerts[1])
$newAlgo = new-object System.Security.Cryptography.SHA1Managed;
$newSigBytes = [convert]::FromBase64String($signature)
$newMessageBytes = [System.Text.Encoding]::UTF8.getBytes($message)
if($newSigBytes -eq $sigBytes){Write-Host "Both SigByte Arrays are equal"}else{Write-host "The Sig Bytes are differnet for some reason";read-host}
$blahCert.PublicKey.Key.VerifyData($newMessageBytes,$newAlgo,$newSigBytes)
$blahCert.PublicKey.Key.VerifyData($dataBytes,$algo,$sigBytes)
#>





