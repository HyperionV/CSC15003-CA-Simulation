#include "KeyGen.h"

// Tạo private keykey
EVP_PKEY* generateECDSAKey() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx) {
        std::cerr << "ERROR: Can't create key context!\n";
        return nullptr;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        std::cerr << "ERROR: Can't initialize keygen!\n";
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0) {
        std::cerr << "ERROR: Can't set curve!\n";
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        std::cerr << "ERROR: Can't generate EC key!\n";
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

void saveToPKCS12(const string& p12File, const string& password, EVP_PKEY* pkey, X509* cert) {
    PKCS12* p12 = PKCS12_create(password.c_str(), "MyCA", pkey, cert, NULL, 0, 0, 0, 0, 0);
    FILE* file = fopen(p12File.c_str(), "wb");
    i2d_PKCS12_fp(file, p12);
    fclose(file);
    PKCS12_free(p12);
}

string getPrivateKeyString(EVP_PKEY* pkey) {
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL);

    char* keyData;
    long len = BIO_get_mem_data(bio, &keyData);
    string privateKey(keyData, len);

    BIO_free(bio);
    return privateKey;
}

string getPublicKeyString(EVP_PKEY* pkey) {
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, pkey);

    char* keyData;
    long len = BIO_get_mem_data(bio, &keyData);
    string publicKey(keyData, len);

    BIO_free(bio);
    return publicKey;
}