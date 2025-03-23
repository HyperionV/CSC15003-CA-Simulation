#include "KeyGen.h"

// Tạo private keykey
EVP_PKEY* generateECDSAKey() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx) {
        cerr << "ERROR: Can't create key context!\n";
        return nullptr;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        cerr << "ERROR: Can't initialize keygen!\n";
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0) {
        cerr << "ERROR: Can't set curve!\n";
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        cerr << "ERROR: Can't generate EC key!\n";
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

// Save Key đến PKS12 
void saveToPKCS12(const string& p12File, const string& password, EVP_PKEY* pkey, X509* cert) {
    PKCS12* p12 = PKCS12_create(password.c_str(), "MyCA", pkey, cert, NULL, 0, 0, 0, 0, 0);
    FILE* file = fopen(p12File.c_str(), "wb");
    i2d_PKCS12_fp(file, p12);
    fclose(file);
    PKCS12_free(p12);
}

// tạo chứng chỉ giả (chỉ để test hàm tạo key)
X509* generateSelfSignedCert(EVP_PKEY* pkey) {
    X509* cert = X509_new();
    if (!cert) {
        cout << "ERROR CREATING CERTIFICATE" << endl;
        return nullptr;
    }

    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L); // 1 năm

    X509_set_pubkey(cert, pkey);

    X509_NAME* name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"MyCA", -1, -1, 0);
    X509_set_issuer_name(cert, name);

    if (!X509_sign(cert, pkey, EVP_sha256())) {
        cout << "ERROR: Can't Sign CA\n";
        X509_free(cert);
        return nullptr;
    }

    return cert;
}


// g++ KeyGen.cpp -o generate_p12 -lssl -lcrypto
//./generate_p12
//openssl pkcs12 -info -in my_key.p12 -nocerts -nodes

// int main() {
//     string p12File = "my_key.p12";
//     string password = "1";

//     EVP_PKEY* pkey = generateECDSAKey();
//     if (!pkey) return 1;

//     X509* cert = generateSelfSignedCert(pkey);
//     if (!cert) {
//         EVP_PKEY_free(pkey);
//         return 1;
//     }
    
//     saveToPKCS12(p12File, password, pkey, cert);

//     EVP_PKEY_free(pkey);
//     X509_free(cert);

//     return 0;
// }