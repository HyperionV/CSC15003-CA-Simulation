#include "CA.h"
#include <iostream>

int main() {
    // Tạo một đối tượng CA với thông tin nhập từ người dùng
    cout << "Please enter CA information:" << endl;
    CA userCA;

    // Hiển thị thông tin CA
    cout << "\nCA Information:" << endl;
    userCA.displayInfo();
    cout << endl;

    // Tạo một chứng chỉ mới
    // string domain;
    // cout << "Enter the domain for the certificate: ";
    // getline(cin, domain);
    // userCA.generateCertificate(domain);

    return 0;
}