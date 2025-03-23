#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include "sqlite3.h"
#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <openssl/bio.h>
#include <ctime>
#include <sstream>
#include "D:\CSC15003-CA-Simulation\SQLite_Database\databaseFunc.cpp"
#include <D:\CSC15003-CA-Simulation\Key-gen\KeyGen.cpp>

using namespace std;

class CA {
private:
    // Private key của CA (lưu trong memory)
    EVP_PKEY* _caPrivateKey;

    // Chứng chỉ của CA (lưu trong memory)
    X509* _caCertificate;

    // Kết nối đến cơ sở dữ liệu SQLite
    sqlite3* _db;

    // Thông tin về CA
    std::string _countryName;
    std::string _organization;
    std::string _commonName;

    // Serial number counter (lưu trong database)
    long _nextSerialNumber;

    // Cấu hình CA
    int _defaultValidityDays; // Thời hạn hiệu lực mặc định của chứng chỉ
    int _keySize;             // Kích thước khóa mặc định

public:
    // Constructor và Destructor
    CA();
    ~CA();

    // Các phương thức
    bool initializeDatabase(const std::string& dbPath); // Khởi tạo database
    bool loadCA(const std::string& privateKeyPEM, const std::string& certificatePEM); // Load CA từ PEM
    bool issueCertificate(const std::string& commonName, const std::string& publicKeyPEM); // Cấp chứng chỉ
    bool revokeCertificate(const std::string& serialNumber); // Thu hồi chứng chỉ
    std::string getCertificate(const std::string& serialNumber); // Lấy chứng chỉ từ database
    // void log(const std::string& message); // Ghi log (có thể lưu vào database)
    bool createCSR(const std::string& commonName, const std::string& country, const std::string& organization, const std::string& publicKeyPEM,
        int userID);
    std::string signCSR(const std::string &csrPEM);
    bool cancelCertificate(const std::string& serialNumber);
};
