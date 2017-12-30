# Posh-Jwt
Powershell implementation of the JSON Web Tokens standard [RFC 7519](https://tools.ietf.org/html/rfc7519)
With functions to create and validate JSON Web Tokens leveraging native powershell and .net classes available on both 

## Description
Posh-Jwt hopes to bring JWT capabilities to powershell scripts and programs in an easy to implement and Powershell-native way.
This project is very much a work in progress, please don't toss it into production without first testing it thoroughly.

### Usage
Download or clone, then simply dot source the functions.ps1 file in your project.  I am working towards making this a module as well, but for the time being simply add the folloing line to your existing scripts:
. ./functions.ps1

Then you can call the following commands to test out a default token:

$header = new-jwtheader
$payload = new-jwtpayload
$token = new-jwt -header $header -payload $payload -secret 'yoursecrethere'
$token
Test-Jwt -token $token -secret 'yousecrethere' #will return true on valid token, or false on invalid token with errors thrown for any issues found with the token

#### Notes
The results of New-jwtHeader and New-JwtPayload are both hashtables, you can edit them as your implementation deems necessary.

#### Todos
1. Comments / Help data
2. go back through the RFC and implement more nuanced scenarios
3. RS256
4. Certificate support on non-windows machines

#### Compatibility
I have done limited testing on:
1. Windows (powershell version 5.1)
2. OSX (powershell 6.0.0 beta (core))
3. ubuntu 16.04

**Note:**Certificate support is ONLY available on Windows (due to integration with the certificate store)
