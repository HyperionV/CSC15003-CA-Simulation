#include <iostream>
#include <string>
#include "sqlite3.h"

using namespace std;

bool executeQuery(sqlite3* db, const string& sql);

bool insertCertificate(sqlite3* db, const string& certVersion, const string& signatureAlgorithm,
    const string& serialNumber, const string& issuerName, int userID,
    const string& validFrom, const string& validTo, const string& publicKey, const string& status);

bool deleteCertificate(sqlite3* db, int certificateID);

bool insertCertificateRequest(sqlite3* db, int userID, const string& publicKey, const string& commonName,
    const string& organization, const string& country,
    const string& reqStatus, const string& requestAt, const string& approvedAt);

bool deleteCertificateRequest(sqlite3* db, int requestID);

bool insertRevokedCertificate(sqlite3* db, int certificateID, const string& reason, const string& revokedTime);

bool deleteRevokedCertificate(sqlite3* db, int revokeID);

bool insertUser(sqlite3* db, const string& username, const string& password, const string& email, const string& role);

bool deleteUser(sqlite3* db, int userID);

bool insertLog(sqlite3* db, const string& action, int userID, int objectID, const string& time);

bool deleteLog(sqlite3* db, int logID);