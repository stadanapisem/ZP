# Data Security Project

Class used to facilitate creating an X.509v3 certificate using ECDSA signing algorithm. Class has the following functionalities:

- Generating new ECDSA keypair
- Importing/Exporting a keypair
- Signing an X.509v3 certificate
- Exporting generated certificate

In addition it supports only three certificate extensions: Certificate policies, Issuer Alternative Name and Inhibit Any Policy. 

The class uses BouncyCastle java security provider.

This project was done as a part of Data Security course at the University of Belgrade - School of Electrical Engineering.
