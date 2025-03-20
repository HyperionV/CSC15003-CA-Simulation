-- Tạo bảng Users
CREATE TABLE Users (
    UserID INTEGER PRIMARY KEY AUTOINCREMENT,
    Username TEXT NOT NULL,
    Password TEXT NOT NULL,
    Email TEXT NOT NULL,
    Role TEXT CHECK (Role IN ('Admin', 'User')) NOT NULL
);

-- Tạo bảng Certificates
CREATE TABLE Certificates (
    CertificateID INTEGER PRIMARY KEY AUTOINCREMENT,
    CertVersion TEXT NOT NULL,
    SignatureAlgorithm TEXT NOT NULL,
    SerialNumber TEXT NOT NULL,
    IssuerName TEXT NOT NULL,
    UserID INTEGER NOT NULL,
    ValidFrom TEXT NOT NULL,
    ValidTo TEXT NOT NULL,
    PublicKey TEXT NOT NULL,
    Status TEXT NOT NULL,
    FOREIGN KEY (UserID) REFERENCES Users(UserID)
);

-- Tạo bảng CertificateRequests
CREATE TABLE CertificateRequests (
    RequestID INTEGER PRIMARY KEY AUTOINCREMENT,
    UserID INTEGER NOT NULL,
    PublicKey TEXT NOT NULL,
    ReqStatus TEXT NOT NULL,
    RequestAt TEXT NOT NULL,
    ApprovedAt TEXT,
    FOREIGN KEY (UserID) REFERENCES Users(UserID)
);

-- Tạo bảng RevokedCertificates
CREATE TABLE RevokedCertificates (
    RevokeID INTEGER PRIMARY KEY AUTOINCREMENT,
    CertificateID INTEGER NOT NULL,
    Reason TEXT NOT NULL,
    RevokedTime TEXT NOT NULL,
    FOREIGN KEY (CertificateID) REFERENCES Certificates(CertificateID)
);

-- Tạo bảng Logs
CREATE TABLE Logs (
    LogID INTEGER PRIMARY KEY AUTOINCREMENT,
    Action TEXT NOT NULL,
    UserID INTEGER NOT NULL,
    ObjectID INTEGER NOT NULL,
    Time TEXT NOT NULL,
    FOREIGN KEY (UserID) REFERENCES Users(UserID),
    FOREIGN KEY (ObjectID) REFERENCES Certificates(CertificateID)
);
