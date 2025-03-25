#include "CA.h"

// Constructor: Khởi tạo các biến thành viên mặc định
CA::CA()
    : _caPrivateKey(nullptr), _caCertificate(nullptr), _db(nullptr),
      _countryName("VN"), _organization("My CA Organization"), _commonName("My CA"),
      _nextSerialNumber(1), _defaultValidityDays(365), _keySize(2048) {
    // Các khởi tạo bổ sung nếu cần
}

// Destructor: Giải phóng tài nguyên
CA::~CA() {
    if (_caPrivateKey) {
        EVP_PKEY_free(_caPrivateKey);
        _caPrivateKey = nullptr;
    }
    if (_caCertificate) {
        X509_free(_caCertificate);
        _caCertificate = nullptr;
    }
    if (_db) {
        sqlite3_close(_db);
        _db = nullptr;
    }
}

// Khởi tạo kết nối database
bool CA::initializeDatabase(const std::string& dbPath) {
    int rc = sqlite3_open(dbPath.c_str(), &_db);
    if (rc) {
        std::cerr << "Cannot open db: " << sqlite3_errmsg(_db) << std::endl;
        return false;
    } else {
        std::cout << "Open db successfully!" << std::endl;
    }
    // Nếu cần, có thể gọi các hàm tạo bảng ở đây (không bắt buộc)
    return true;
}

// Load CA từ PEM: load private key và certificate từ chuỗi PEM
bool CA::loadCA(const std::string& privateKeyPEM, const std::string& certificatePEM) {
    // Load private key
    BIO* bio = BIO_new_mem_buf(privateKeyPEM.c_str(), -1);
    if (!bio) {
        std::cerr << "Failed to create BIO for private key" << std::endl;
        return false;
    }
    _caPrivateKey = PEM_read_bio_PrivateKey(bio, NULL, 0, NULL);
    BIO_free(bio);
    if (!_caPrivateKey) {
        std::cerr << "Failed to load CA private key" << std::endl;
        return false;
    }

    // Load certificate
    bio = BIO_new_mem_buf(certificatePEM.c_str(), -1);
    if (!bio) {
        std::cerr << "Failed to create BIO for certificate" << std::endl;
        return false;
    }
    _caCertificate = PEM_read_bio_X509(bio, NULL, 0, NULL);
    BIO_free(bio);
    if (!_caCertificate) {
        std::cerr << "Failed to load CA certificate" << std::endl;
        return false;
    }
    return true;
}

// Phương thức cấp chứng chỉ: tạo thông tin chứng chỉ và lưu vào database
bool CA::issueCertificate(const std::string& commonName, const std::string& publicKeyPEM) {
    // Các thông tin chứng chỉ được giả lập cho ví dụ
    std::string certVersion = "v1.0";
    std::string signatureAlgorithm = "SHA-256";
    // Dùng _nextSerialNumber làm serialNumber
    std::string serialNumber = std::to_string(_nextSerialNumber);
    // Sử dụng thông tin issuer từ CA (ở đây dùng _commonName)
    std::string issuerName = _commonName;
    // Giả sử userID = 1 (điều này có thể thay đổi theo logic của dự án)
    int userID = 1;

    // Lấy thời gian hiện tại cho validFrom
    time_t now = time(0);
    struct tm* ltm = localtime(&now);
    char validFrom[20];
    strftime(validFrom, sizeof(validFrom), "%Y-%m-%d", ltm);

    // Tính validTo bằng cách cộng thêm _defaultValidityDays
    now += static_cast<long long>(_defaultValidityDays) * 24 * 3600;
    ltm = localtime(&now);
    char validTo[20];
    strftime(validTo, sizeof(validTo), "%Y-%m-%d", ltm);

    std::string status = "Active";

    // Gọi hàm insertCertificate từ file database
    if (!_db) {
        std::cerr << "Error: DB didn't create!\n";
        return false;
    }

    bool result = insertCertificate(_db, certVersion, signatureAlgorithm, serialNumber,
                                    issuerName, userID, validFrom, validTo, publicKeyPEM, status);
    if (result) {
        // Tăng serial number cho chứng chỉ tiếp theo
        _nextSerialNumber++;
    }
    return result;
}

// Phương thức thu hồi chứng chỉ: ghi thông tin thu hồi vào database
bool CA::revokeCertificate(const std::string& serialNumber) {
    // Ở đây, giả sử certificateID trùng với serialNumber (chuyển đổi sang số nguyên)
    int certificateID = 0;
    try {
        certificateID = std::stoi(serialNumber);
    } catch (...) {
        std::cerr << "Invalid serial number format" << std::endl;
        return false;
    }
    
    std::string reason = "Revoked by CA";
    // Lấy thời gian hiện tại cho revokedTime
    time_t now = time(0);
    struct tm* ltm = localtime(&now);
    char revokedTime[20];
    strftime(revokedTime, sizeof(revokedTime), "%Y-%m-%d", ltm);

    // Gọi hàm insertRevokedCertificate từ file database
    return insertRevokedCertificate(_db, certificateID, reason, revokedTime);
}

// Phương thức lấy chứng chỉ từ database: ở ví dụ này chỉ trả về chuỗi mô tả
std::string CA::getCertificate(const std::string& serialNumber) {
    // Trong thực tế, bạn sẽ truy vấn database để lấy dữ liệu chứng chỉ theo serialNumber.
    // Ở đây chỉ đơn giản trả về một chuỗi minh họa.
    return "Certificate data for serial number: " + serialNumber;
}


bool CA::createCSR(const std::string& commonName,
    const std::string& country,
    const std::string& organization,
    const std::string& publicKeyPEM,
    int userID) {
    // 1. Tạo CSR mới
    X509_REQ* req = X509_REQ_new();
    if (!req) {
    std::cerr << "Lỗi: Không tạo được CSR" << std::endl;
    return false;
    }
    // Đặt phiên bản cho CSR (phiên bản 1)
    if (X509_REQ_set_version(req, 1) != 1) {
    std::cerr << "Lỗi: Không thể đặt version cho CSR" << std::endl;
    X509_REQ_free(req);
    return false;
    }

    // 2. Thiết lập subject name (thông tin chủ thể) cho CSR
    X509_NAME* subj = X509_NAME_new();
    if (!subj) {
    std::cerr << "Lỗi: Không tạo được X509_NAME" << std::endl;
    X509_REQ_free(req);
    return false;
    }
    // Thêm Country (C)
    if (X509_NAME_add_entry_by_txt(subj, "C", MBSTRING_ASC,
                        reinterpret_cast<const unsigned char*>(country.c_str()),
                        -1, -1, 0) != 1) {
    std::cerr << "Lỗi: Không thêm được trường Country" << std::endl;
    X509_NAME_free(subj);
    X509_REQ_free(req);
    return false;
    }
    // Thêm Organization (O)
    if (X509_NAME_add_entry_by_txt(subj, "O", MBSTRING_ASC,
                        reinterpret_cast<const unsigned char*>(organization.c_str()),
                        -1, -1, 0) != 1) {
    std::cerr << "Lỗi: Không thêm được trường Organization" << std::endl;
    X509_NAME_free(subj);
    X509_REQ_free(req);
    return false;
    }
    // Thêm Common Name (CN)
    if (X509_NAME_add_entry_by_txt(subj, "CN", MBSTRING_ASC,
                        reinterpret_cast<const unsigned char*>(commonName.c_str()),
                        -1, -1, 0) != 1) {
    std::cerr << "Lỗi: Không thêm được trường Common Name" << std::endl;
    X509_NAME_free(subj);
    X509_REQ_free(req);
    return false;
    }
    // Gán subject name cho CSR
    if (X509_REQ_set_subject_name(req, subj) != 1) {
    std::cerr << "Lỗi: Không gán subject name cho CSR" << std::endl;
    X509_NAME_free(subj);
    X509_REQ_free(req);
    return false;
    }
    X509_NAME_free(subj);

    // 3. Thiết lập khóa public vào CSR từ chuỗi PEM do người dùng cung cấp
    BIO* bio = BIO_new_mem_buf(publicKeyPEM.c_str(), -1);
    if (!bio) {
    std::cerr << "Lỗi: Không tạo BIO cho public key" << std::endl;
    X509_REQ_free(req);
    return false;
    }
    EVP_PKEY* pubKey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!pubKey) {
    std::cerr << "Lỗi: Không đọc được public key từ PEM" << std::endl;
    X509_REQ_free(req);
    return false;
    }
    if (X509_REQ_set_pubkey(req, pubKey) != 1) {
    std::cerr << "Lỗi: Không thiết lập public key cho CSR" << std::endl;
    EVP_PKEY_free(pubKey);
    X509_REQ_free(req);
    return false;
    }
    EVP_PKEY_free(pubKey);

    // Lưu ý: Trong thực tế, CSR cần được ký bởi khóa riêng của người gửi để đảm bảo tính hợp lệ.
    // Ở ví dụ này, chúng ta bỏ qua bước ký CSR do không có khóa riêng của người dùng.

    // 4. Chuyển CSR sang định dạng PEM
    BIO* out = BIO_new(BIO_s_mem());
    if (!out) {
    std::cerr << "Lỗi: Không tạo BIO cho output" << std::endl;
    X509_REQ_free(req);
    return false;
    }
    if (PEM_write_bio_X509_REQ(out, req) != 1) {
    std::cerr << "Lỗi: Không chuyển CSR sang PEM" << std::endl;
    BIO_free(out);
    X509_REQ_free(req);
    return false;
    }
    char* pemData = nullptr;
    long pemLen = BIO_get_mem_data(out, &pemData);
    std::string csrPEM(pemData, pemLen);
    BIO_free(out);
    X509_REQ_free(req);

    // 5. Lấy thời gian hiện tại để lưu vào cơ sở dữ liệu
    time_t now = time(nullptr);
    struct tm* ltm = localtime(&now);
    char requestAt[20];
    strftime(requestAt, sizeof(requestAt), "%Y-%m-%d", ltm);

    // 6. Gửi yêu cầu CSR vào cơ sở dữ liệu
    // Ở đây ta sử dụng hàm insertCertificateRequest có sẵn, với trạng thái "Pending"
    if (!insertCertificateRequest(_db, userID, csrPEM, "Pending", requestAt, "", "", "", "")) {
    std::cerr << "Lỗi: Không thể ghi CSR vào database" << std::endl;
    return false;
    }

    std::cout << "CSR đã được tạo và gửi lên database thành công." << std::endl;
    return true;
}

std::string CA::signCSR(const std::string &csrPEM) {
    // 1. Chuyển đổi chuỗi PEM của CSR sang đối tượng X509_REQ
    BIO* bio = BIO_new_mem_buf(csrPEM.c_str(), -1);
    if (!bio) {
        std::cerr << "Lỗi: Không tạo được BIO từ CSR PEM" << std::endl;
        return "";
    }
    X509_REQ* req = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!req) {
        std::cerr << "Lỗi: Không đọc được CSR từ PEM" << std::endl;
        return "";
    }

    // 2. Tạo chứng chỉ X509 mới
    X509* cert = X509_new();
    if (!cert) {
        std::cerr << "Lỗi: Không tạo được chứng chỉ X509" << std::endl;
        X509_REQ_free(req);
        return "";
    }

    // 3. Đặt phiên bản cho chứng chỉ (phiên bản 3: value = 2)
    if (X509_set_version(cert, 2) != 1) {
        std::cerr << "Lỗi: Không đặt được phiên bản cho chứng chỉ" << std::endl;
        X509_free(cert);
        X509_REQ_free(req);
        return "";
    }

    // 4. Thiết lập serial number cho chứng chỉ (sử dụng _nextSerialNumber của CA)
    ASN1_INTEGER* asn1_serial = ASN1_INTEGER_new();
    if (!asn1_serial) {
        std::cerr << "Lỗi: Không tạo được ASN1_INTEGER cho serial" << std::endl;
        X509_free(cert);
        X509_REQ_free(req);
        return "";
    }
    ASN1_INTEGER_set(asn1_serial, _nextSerialNumber);
    if (X509_set_serialNumber(cert, asn1_serial) != 1) {
        std::cerr << "Lỗi: Không thiết lập serial number" << std::endl;
        ASN1_INTEGER_free(asn1_serial);
        X509_free(cert);
        X509_REQ_free(req);
        return "";
    }
    ASN1_INTEGER_free(asn1_serial);
    _nextSerialNumber++;  // Tăng serial cho lần cấp tiếp theo

    // 5. Thiết lập Issuer cho chứng chỉ từ thông tin của CA
    if (_caCertificate) {
        X509_NAME* issuerName = X509_get_subject_name(_caCertificate);
        if (X509_set_issuer_name(cert, issuerName) != 1) {
            std::cerr << "Lỗi: Không thiết lập issuer từ chứng chỉ CA" << std::endl;
            X509_free(cert);
            X509_REQ_free(req);
            return "";
        }
    } else {
        // Nếu không có certificate CA, dùng thông tin lưu trong class CA
        X509_NAME* issuerName = X509_NAME_new();
        if (!issuerName) {
            std::cerr << "Lỗi: Không tạo được issuer name" << std::endl;
            X509_free(cert);
            X509_REQ_free(req);
            return "";
        }
        X509_NAME_add_entry_by_txt(issuerName, "C", MBSTRING_ASC,
                                   reinterpret_cast<const unsigned char*>(_countryName.c_str()),
                                   -1, -1, 0);
        X509_NAME_add_entry_by_txt(issuerName, "O", MBSTRING_ASC,
                                   reinterpret_cast<const unsigned char*>(_organization.c_str()),
                                   -1, -1, 0);
        X509_NAME_add_entry_by_txt(issuerName, "CN", MBSTRING_ASC,
                                   reinterpret_cast<const unsigned char*>(_commonName.c_str()),
                                   -1, -1, 0);
        if (X509_set_issuer_name(cert, issuerName) != 1) {
            std::cerr << "Lỗi: Không thiết lập issuer name" << std::endl;
            X509_NAME_free(issuerName);
            X509_free(cert);
            X509_REQ_free(req);
            return "";
        }
        X509_NAME_free(issuerName);
    }

    // 6. Lấy thông tin subject từ CSR và thiết lập vào chứng chỉ
    X509_NAME* subj = X509_REQ_get_subject_name(req);
    if (X509_set_subject_name(cert, subj) != 1) {
        std::cerr << "Lỗi: Không thiết lập subject name" << std::endl;
        X509_free(cert);
        X509_REQ_free(req);
        return "";
    }

    // 7. Lấy khóa public từ CSR và thiết lập vào chứng chỉ
    EVP_PKEY* pubKey = X509_REQ_get_pubkey(req);
    if (!pubKey) {
        std::cerr << "Lỗi: Không lấy được khóa public từ CSR" << std::endl;
        X509_free(cert);
        X509_REQ_free(req);
        return "";
    }
    if (X509_set_pubkey(cert, pubKey) != 1) {
        std::cerr << "Lỗi: Không thiết lập khóa public cho chứng chỉ" << std::endl;
        EVP_PKEY_free(pubKey);
        X509_free(cert);
        X509_REQ_free(req);
        return "";
    }
    EVP_PKEY_free(pubKey);

    // 8. Thiết lập thời gian hiệu lực cho chứng chỉ
    // notBefore: thời điểm hiện tại; notAfter: hiện tại + _defaultValidityDays
    time_t now = time(NULL);
    ASN1_TIME* notBefore = ASN1_TIME_new();
    ASN1_TIME* notAfter = ASN1_TIME_new();
    if (!notBefore || !notAfter) {
        std::cerr << "Lỗi: Không tạo được thời gian hiệu lực" << std::endl;
        if (notBefore) ASN1_TIME_free(notBefore);
        if (notAfter) ASN1_TIME_free(notAfter);
        X509_free(cert);
        X509_REQ_free(req);
        return "";
    }
    ASN1_TIME_set(notBefore, now);
    ASN1_TIME_set(notAfter, now + static_cast<long long>(_defaultValidityDays) * 24 * 3600);
    if (X509_set_notBefore(cert, notBefore) != 1 ||
        X509_set_notAfter(cert, notAfter) != 1) {
        std::cerr << "Lỗi: Không thiết lập thời gian hiệu lực" << std::endl;
        ASN1_TIME_free(notBefore);
        ASN1_TIME_free(notAfter);
        X509_free(cert);
        X509_REQ_free(req);
        return "";
    }
    ASN1_TIME_free(notBefore);
    ASN1_TIME_free(notAfter);

    // 9. Ký chứng chỉ bằng private key của CA
    if (!_caPrivateKey) {
        std::cerr << "Lỗi: Private key của CA chưa được load" << std::endl;
        X509_free(cert);
        X509_REQ_free(req);
        return "";
    }
    if (X509_sign(cert, _caPrivateKey, EVP_sha256()) == 0) {
        std::cerr << "Lỗi: Ký chứng chỉ thất bại" << std::endl;
        X509_free(cert);
        X509_REQ_free(req);
        return "";
    }

    // 10. Chuyển chứng chỉ đã ký sang định dạng PEM để trả về
    BIO* bioOut = BIO_new(BIO_s_mem());
    if (!bioOut) {
        std::cerr << "Lỗi: Không tạo được BIO cho output chứng chỉ" << std::endl;
        X509_free(cert);
        X509_REQ_free(req);
        return "";
    }
    if (PEM_write_bio_X509(bioOut, cert) != 1) {
        std::cerr << "Lỗi: Ghi chứng chỉ ra PEM thất bại" << std::endl;
        BIO_free(bioOut);
        X509_free(cert);
        X509_REQ_free(req);
        return "";
    }
    char* pemCertData = nullptr;
    long pemCertLen = BIO_get_mem_data(bioOut, &pemCertData);
    std::string certPEM(pemCertData, pemCertLen);

    // Cleanup
    BIO_free(bioOut);
    X509_free(cert);
    X509_REQ_free(req);

    return certPEM;
}

bool CA::cancelCertificate(const std::string &serialNumber) {
    // Chuyển đổi serialNumber (dạng chuỗi) sang số nguyên (certificateID)
    int certificateID = 0;
    try {
        certificateID = std::stoi(serialNumber);
    } catch (...) {
        std::cerr << "Lỗi: Định dạng serial number không hợp lệ." << std::endl;
        return false;
    }

    // Gọi hàm deleteCertificate để xóa chứng chỉ khỏi database
    if (!deleteCertificate(_db, certificateID)) {
        std::cerr << "Lỗi: Xóa chứng chỉ khỏi database thất bại." << std::endl;
        return false;
    }

    // Ghi log hành động hủy cấp chứng chỉ (nếu cần)
    time_t now = time(nullptr);
    struct tm* ltm = localtime(&now);
    char logTime[20];
    strftime(logTime, sizeof(logTime), "%Y-%m-%d %H:%M:%S", ltm);
    insertLog(_db, "Cancel Certificate", 0, certificateID, logTime);

    std::cout << "Chứng chỉ với serial number " << serialNumber << " đã được hủy và xóa khỏi database." << std::endl;
    return true;
}

