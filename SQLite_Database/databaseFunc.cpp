#include <iostream>
#include <string>
#include <sqlite3.h>

using namespace std;

// Hàm thực thi SQL (INSERT, DELETE)
bool executeQuery(sqlite3* db, const string& sql) {
    char* errMsg = nullptr;
    if (sqlite3_exec(db, sql.c_str(), nullptr, 0, &errMsg) != SQLITE_OK) {
        cerr << "Lỗi SQLite: " << errMsg << endl;
        sqlite3_free(errMsg);
        return false;
    }
    return true;
}

// ======================== INSERT & DELETE HÀM CHO CÁC BẢNG ========================

// Thêm chứng chỉ vào bảng Certificates
bool insertCertificate(sqlite3* db, const string& certVersion, const string& signatureAlgorithm, 
                       const string& serialNumber, const string& issuerName, int userID, 
                       const string& validFrom, const string& validTo, const string& publicKey, const string& status) {
    string sql = "INSERT INTO Certificates (CertVersion, SignatureAlgorithm, SerialNumber, IssuerName, UserID, ValidFrom, ValidTo, PublicKey, Status) VALUES ('"
                + certVersion + "', '" + signatureAlgorithm + "', '" + serialNumber + "', '" + issuerName + "', "
                + to_string(userID) + ", '" + validFrom + "', '" + validTo + "', '" + publicKey + "', '" + status + "');";
    return executeQuery(db, sql);
}

// Xóa chứng chỉ theo CertificateID
bool deleteCertificate(sqlite3* db, int certificateID) {
    string sql = "DELETE FROM Certificates WHERE CertificateID = " + to_string(certificateID) + ";";
    return executeQuery(db, sql);
}

// Thêm yêu cầu cấp chứng chỉ vào CertificateRequests
bool insertCertificateRequest(sqlite3* db, int userID, const string& publicKey, const string& reqStatus, const string& requestAt, const string& approvedAt) {
    string sql = "INSERT INTO CertificateRequests (UserID, PublicKey, ReqStatus, RequestAt, ApprovedAt) VALUES ("
                + to_string(userID) + ", '" + publicKey + "', '" + reqStatus + "', '" + requestAt + "', " 
                + (approvedAt.empty() ? "NULL" : "'" + approvedAt + "'") + ");";
    return executeQuery(db, sql);
}

// Xóa yêu cầu cấp chứng chỉ theo RequestID
bool deleteCertificateRequest(sqlite3* db, int requestID) {
    string sql = "DELETE FROM CertificateRequests WHERE RequestID = " + to_string(requestID) + ";";
    return executeQuery(db, sql);
}

// Thêm chứng chỉ bị thu hồi vào RevokedCertificates
bool insertRevokedCertificate(sqlite3* db, int certificateID, const string& reason, const string& revokedTime) {
    string sql = "INSERT INTO RevokedCertificates (CertificateID, Reason, RevokedTime) VALUES ("
                + to_string(certificateID) + ", '" + reason + "', '" + revokedTime + "');";
    return executeQuery(db, sql);
}

// Xóa chứng chỉ bị thu hồi theo RevokeID
bool deleteRevokedCertificate(sqlite3* db, int revokeID) {
    string sql = "DELETE FROM RevokedCertificates WHERE RevokeID = " + to_string(revokeID) + ";";
    return executeQuery(db, sql);
}

// Thêm user vào bảng Users
bool insertUser(sqlite3* db, const string& username, const string& password, const string& email, const string& role) {
    string sql = "INSERT INTO Users (Username, Password, Email, Role) VALUES ('" + username + "', '" + password + "', '" + email + "', '" + role + "');";
    return executeQuery(db, sql);
}

// Xóa user theo UserID
bool deleteUser(sqlite3* db, int userID) {
    string sql = "DELETE FROM Users WHERE UserID = " + to_string(userID) + ";";
    return executeQuery(db, sql);
}

// Ghi log vào bảng Logs
bool insertLog(sqlite3* db, const string& action, int userID, int objectID, const string& time) {
    string sql = "INSERT INTO Logs (Action, UserID, ObjectID, Time) VALUES ('"
                + action + "', " + to_string(userID) + ", " + to_string(objectID) + ", '" + time + "');";
    return executeQuery(db, sql);
}

// Xóa log theo LogID
bool deleteLog(sqlite3* db, int logID) {
    string sql = "DELETE FROM Logs WHERE LogID = " + to_string(logID) + ";";
    return executeQuery(db, sql);
}

// ======================== CHƯƠNG TRÌNH CHÍNH ========================
int main() {
    sqlite3* db;
    int rc = sqlite3_open("MHUD.db", &db);

    if (rc) {
        cerr << "Cannot open db: " << sqlite3_errmsg(db) << endl;
        return 1;
    } else {
        cout << "Open db successfully!" << endl;
    }

    // Ví dụ: Thêm một chứng chỉ mới
    insertCertificate(db, "v1.0", "SHA-256", "123456789", "MHUD CA", 1, "2025-01-01", "2030-01-01", "PUBLIC_KEY_DATA", "Active");

    // Ví dụ: Xóa chứng chỉ có ID = 1
    deleteCertificate(db, 1);

    // Ví dụ: Thêm yêu cầu cấp chứng chỉ
    insertCertificateRequest(db, 1, "PUBLIC_KEY_REQUEST", "Pending", "2025-03-19", "");

    // Ví dụ: Xóa yêu cầu có ID = 1
    deleteCertificateRequest(db, 1);

    // Ví dụ: Thêm chứng chỉ bị thu hồi
    insertRevokedCertificate(db, 1, "Compromised", "2025-03-19");

    // Ví dụ: Xóa chứng chỉ bị thu hồi có ID = 1
    deleteRevokedCertificate(db, 1);

    // Ví dụ: Ghi log
    insertLog(db, "Issue Certificate", 1, 2, "2025-03-19 12:00:00");

    // Ví dụ: Xóa log có ID = 1
    deleteLog(db, 1);

    sqlite3_close(db);
    return 0;
}
