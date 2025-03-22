#define _CRT_SECURE_NO_WARNINGS
#include <cstdio>
#include <openssl/applink.c>
#include <iostream>
#include <openssl/ec.h>
#include <string>  
#include <openssl/pkcs12.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

using namespace std;

EVP_PKEY* generateECDSAKey();
void saveToPKCS12(const string& p12File, const string& password, EVP_PKEY* pkey, X509* cert);