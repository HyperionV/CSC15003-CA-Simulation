Cách cài đặt OpenSSL trong Visual Studio

Bước 1: Cài đặt vcpkg
- Vào đường dẫn https://github.com/microsoft/vcpkg.git để tải file zip về và giải nén
- Sau khi giải nén thành công, chạy file bootstrap-vcpkg.bat
- Sau khi build thành công, file vcpkg.exe sẽ được tạo ra trong thư mục vcpkg
- Mở CMD/PowerShell, cd đến folder đã giải nén, chạy lệnh .\vcpkg integrate install
- Lệnh này sẽ tự động thêm các thư viện đã cài đặt bằng vcpkg vào các dự án Visual Studio.

Bước 2: Sử dụng vcpkg để cài đặt OpenSSL
- Chạy lệnh .\vcpkg install openssl:x64-windows để cài đặt OpenSSL
- OpenSSL sẽ được tự động cài đặt và có thể được include trong Visual Studio

Hoặc, chạy câu lệnh sau trong CMD/PowerShell:
git clone https://github.com/microsoft/vcpkg.git && cd vcpkg && .\bootstrap-vcpkg.bat && .\vcpkg integrate install && .\vcpkg install openssl:x64-windows



