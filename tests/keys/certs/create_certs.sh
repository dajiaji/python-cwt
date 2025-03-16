#!/bin/bash
# Create a self-signed root CA certificate, server certificate, and convert them to PEM format
# The server certificate is signed by the root CA certificate
# The root CA certificate is created with CA:TRUE, keyCertSign, and cRLSign extensions
# The server certificate is created with the subjectAltName extension

# Create a self-signed root CA certificate
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl ec -in ca.key -out ca_key.der -outform DER
openssl ec -inform DER -in ca_key.der -out ca_key.pem -outform PEM
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt -config openssl_ca.cnf
openssl x509 -in ca.crt -text -noout
openssl x509 -in ca.crt -out ca.der -outform DER
openssl x509 -inform DER -in ca.der -out ca.pem -outform PEM

# Create a server certificate signed by the root CA certificate
openssl ecparam -name prime256v1 -genkey -noout -out server.key
openssl ec -in server.key -out server_key.der -outform DER
openssl ec -inform DER -in server_key.der -out server_key.pem -outform PEM
openssl req -new -key server.key -out server.csr -config openssl_server.cnf
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -sha256 -extfile openssl_server.cnf -extensions v3_req
openssl x509 -in server.crt -text -noout
openssl x509 -in server.crt -out server.der -outform DER
openssl x509 -inform DER -in server.der -out server.pem -outform PEM
