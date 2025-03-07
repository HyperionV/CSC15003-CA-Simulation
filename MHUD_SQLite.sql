/* Bảng User, có thể không sử dụng
CREATE TABLE Users (
    UserID INTEGER PRIMARY KEY,
    Username TEXT NOT NULL,
    Password TEXT NOT NULL,
    Email TEXT NOT NULL,
    Role TEXT CHECK (Role IN ('Admin', 'User')) NOT NULL
);
*/

-- Lưu thông tin về các chứng chỉ đã cấp
CREATE TABLE Certificates (
    CertificateID INTEGER PRIMARY KEY,
    CertVersion TEXT NOT NULL,
    SignatureAlgorithm TEXT NOT NULL,
    SerialNumber TEXT NOT NULL,
    IssuerName TEXT NOT NULL,
    SubjectID INTEGER NOT NULL,
    ValidFrom DATETIME NOT NULL,
    ValidTo DATETIME NOT NULL,
    PublicKey TEXT NOT NULL,
    Status TEXT NOT NULL
    -- FOREIGN KEY (SubjectID) REFERENCES Users(UserID) -- Khóa ngoại nối với bảng Users
);

-- Quản lý các yêu cầu cấp chứng chỉ
CREATE TABLE CertificateRequests (
    RequestID INTEGER PRIMARY KEY,
    SubjectID INTEGER NOT NULL,
    PublicKey TEXT NOT NULL,
    ReqStatus TEXT NOT NULL,
    RequestAt DATETIME NOT NULL,
    ApprovedAt DATETIME
    -- FOREIGN KEY (SubjectID) REFERENCES Users(UserID)
);

/* Bảng chứa certificate đã bị thu hồi, có thể không cần
CREATE TABLE RevokedCertificates (
    RevokeID INTEGER PRIMARY KEY,
    CertificateID INTEGER NOT NULL,
    Reason TEXT NOT NULL,
    RevokedTime DATETIME NOT NULL,
    FOREIGN KEY (CertificateID) REFERENCES Certificates(CertificateID)
);
*/ 

-- Ghi lại lịch sử hoạt động
CREATE TABLE Logs (
    LogID INTEGER PRIMARY KEY,
    Action TEXT NOT NULL,
    DoneBy INTEGER NOT NULL,
    ObjectID INTEGER NOT NULL,
    Time DATETIME NOT NULL,
    -- FOREIGN KEY (DoneBy) REFERENCES Users(UserID),
    FOREIGN KEY (ObjectID) REFERENCES Certificates(CertificateID)
);
