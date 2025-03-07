#include <iostream>
#include <openssl/ec.h>
#include <string>  
#include <openssl/pkcs12.h>

using namespace std;

EVP_PKEY* generateECDSAKey() {
    EC_KEY* ecKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ecKey || !EC_KEY_generate_key(ecKey)) { //Sinh một cặp khóa riêng và công khai.
        std::cerr << "ERROR: Can't create key!\n";
        if (ecKey) EC_KEY_free(ecKey);
        return nullptr;
    }

    // Chuyển đổi EC_KEY sang EVP_PKEY để dùng với OpenSSL
    EVP_PKEY* pkey = EVP_PKEY_new();
    if (!EVP_PKEY_assign_EC_KEY(pkey, ecKey)) {
        std::cerr << "ERROR: Can't paste EC_KEY to EVP_PKEY!\n";
        EVP_PKEY_free(pkey);
        return nullptr;
    }

    return pkey;
}
void saveToPKCS12(const string& p12File, const string& password, EVP_PKEY* pkey, X509* cert) {
    PKCS12* p12 = PKCS12_create(password.c_str(), "MyCA", pkey, cert, NULL, 0, 0, 0, 0, 0);
    FILE* file = fopen(p12File.c_str(), "wb");
    i2d_PKCS12_fp(file, p12);
    fclose(file);
    PKCS12_free(p12);
}

// Hàm tạo chứng chỉ giả (chỉ để thử nghiệm, không có giá trị thực tế)
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

int main() {
    string p12File = "my_key.p12";
    string password = "1";

    EVP_PKEY* pkey = generateECDSAKey();
    if (!pkey) return 1;

    X509* cert = generateSelfSignedCert(pkey);
    if (!cert) {
        EVP_PKEY_free(pkey);
        return 1;
    }
    
    saveToPKCS12(p12File, password, pkey, cert);

    // Giải phóng bộ nhớ
    EVP_PKEY_free(pkey);
    X509_free(cert);

    return 0;
}