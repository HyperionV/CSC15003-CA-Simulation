#include "/CSC15003-CA-Simulation/Key-gen/KeyGen.h"
#include "/CSC15003-CA-Simulation/Certificate_Authority/CA.h"
#include <openssl/applink.c>
#include <fstream>

void printMenu() {
    std::cout << "\n=== Certificate Authority (CA) System ===\n";
    std::cout << "1. New CA\n";
    std::cout << "5. Exit\n";
    std::cout << "Choose: ";
}

int main() {
    CA myCA;
    EVP_PKEY* pkey = generateECDSAKey();
    std::string priKey = getPrivateKeyString(pkey);
    string pubKey = getPublicKeyString(pkey);

    // 2️⃣ Chạy vòng lặp để nhập lệnh từ người dùng
    int choice;

    if (!myCA.initializeDatabase("D:/CSC15003-CA-Simulation/SQLite_Database/MHUD.db")) {
        std::cerr << "Database initialization failed!" << std::endl;
        return 1;
    }

    while (true) {
        printMenu();
        std::cin >> choice;
        std::cin.ignore();

        if (choice == 1) {
            // Cấp chứng chỉ mới
            std::string username;
            std::cout << "Enter Name user: ";
            std::getline(std::cin, username);

            std::string userKey, userCert;
            if (myCA.issueCertificate(username, pubKey)) {
                std::cout << "Certificate for" << username << " provided!\n";
            }
            else {
                std::cerr << "Error for providing CA!\n";
            }
        }
        /*
        else if (choice == 2) {
            // Xác thực chứng chỉ
            std::string certPath;
            std::cout << "Nhập đường dẫn chứng chỉ: ";
            std::getline(std::cin, certPath);

            std::ifstream userCertFile(certPath);
            if (!userCertFile) {
                std::cerr << "❌ Không tìm thấy file chứng chỉ!\n";
                continue;
            }

            std::stringstream certBuffer;
            certBuffer << userCertFile.rdbuf();
            std::string userCert = certBuffer.str();

            if (myCA.verifyCertificate(userCert)) {
                std::cout << "✅ Chứng chỉ hợp lệ!\n";
            }
            else {
                std::cerr << "❌ Chứng chỉ không hợp lệ hoặc đã bị thu hồi!\n";
            }
        }
        else if (choice == 3) {
            // Thu hồi chứng chỉ
            std::string username;
            std::cout << "Nhập tên người dùng cần thu hồi chứng chỉ: ";
            std::getline(std::cin, username);

            if (myCA.revokeCertificate(username)) {
                std::cout << "✅ Chứng chỉ của " << username << " đã bị thu hồi!\n";
            }
            else {
                std::cerr << "❌ Không tìm thấy chứng chỉ hoặc thu hồi thất bại!\n";
            }
        }
        else if (choice == 4) {
            // Xuất danh sách thu hồi (CRL)
            std::string crlData = myCA.generateCRL();
            std::ofstream crlFile("ca_crl.pem");
            crlFile << crlData;
            std::cout << "✅ Danh sách CRL đã được xuất!\n";
        }
        */
        else if (choice == 5) {
            // Thoát chương trình
            std::cout << "Exit program CA.\n";
            break;
        }
        else {
            std::cout << "Your choise is not suitable\n";
        }
    }

    return 0;
}
