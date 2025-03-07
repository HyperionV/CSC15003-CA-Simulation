
USE master;
GO

-- Kill all connections to the database if it exists
IF EXISTS (SELECT name FROM sys.databases WHERE name = 'MHUD')
BEGIN
    ALTER DATABASE MHUD SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
    
    DROP DATABASE MHUD;
END
GO

CREATE DATABASE MHUD;
GO

USE MHUD;
GO

-- Bảng User, có thể không sử dụng
CREATE TABLE Users (
    UserID INT PRIMARY KEY IDENTITY(1,1),
    Username NVARCHAR(50) NOT NULL,
    Password NVARCHAR(100) NOT NULL,
    Email NVARCHAR(100) NOT NULL,
    Role NVARCHAR(10) CHECK (Role IN ('Admin', 'User')) NOT NULL
);


-- Lưu thông tin về các chứng chỉ đã cấp
CREATE TABLE Certificates (
    CertificateID INT PRIMARY KEY IDENTITY(1,1),
    CertVersion NVARCHAR(20) NOT NULL,
    SignatureAlgorithm NVARCHAR(50) NOT NULL,
    SerialNumber NVARCHAR(100) NOT NULL,
    IssuerName NVARCHAR(200) NOT NULL,
    UserID INT NOT NULL,
    ValidFrom DATETIME NOT NULL,
    ValidTo DATETIME NOT NULL,
    PublicKey NVARCHAR(MAX) NOT NULL,
    Status NVARCHAR(20) NOT NULL,
    FOREIGN KEY (UserID) REFERENCES Users(UserID) -- Khóa ngoại nối với bảng Users
);

-- Quản lý các yêu cầu cấp chứng chỉ
CREATE TABLE CertificateRequests (
    RequestID INT PRIMARY KEY IDENTITY(1,1),
    UserID INT NOT NULL,
    PublicKey NVARCHAR(MAX) NOT NULL,
    ReqStatus NVARCHAR(20) NOT NULL,
    RequestAt DATETIME NOT NULL,
    ApprovedAt DATETIME,
    FOREIGN KEY (UserID) REFERENCES Users(UserID)
);

-- Bảng chứa certificate đã bị thu hồi, có thể không cần
-- CREATE TABLE RevokedCertificates (
--     RevokeID INT PRIMARY KEY IDENTITY(1,1),
--     CertificateID INT NOT NULL,
--     Reason NVARCHAR(200) NOT NULL,
--     RevokedTime DATETIME NOT NULL,
--     FOREIGN KEY (CertificateID) REFERENCES Certificates(CertificateID)
-- );
 

-- Ghi lại lịch sử hoạt động
CREATE TABLE Logs (
    LogID INT PRIMARY KEY IDENTITY(1,1),
    Action NVARCHAR(100) NOT NULL,
    UserID INT NOT NULL,
    ObjectID INT NOT NULL,
    Time DATETIME NOT NULL,
    FOREIGN KEY (UserID) REFERENCES Users(UserID),
    FOREIGN KEY (ObjectID) REFERENCES Certificates(CertificateID)
);
GO
