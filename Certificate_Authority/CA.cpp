#include "CA.h"
#include <iostream>

// Constructor with parameters implementation
CA::CA(const string& cn, const string& on, const string& ou,
       const string& loc, const string& st, const string& cou,
       const string& email)
    : commonName(cn), organizationName(on), organizationalUnit(ou),
      locality(loc), state(st), country(cou), emailAddress(email) {}

// Constructor for user input implementation
CA::CA() {
    cout << "Enter Common Name: ";
    getline(cin, commonName);

    cout << "Enter Organization Name: ";
    getline(cin, organizationName);

    cout << "Enter Organizational Unit: ";
    getline(cin, organizationalUnit);

    cout << "Enter Locality: ";
    getline(cin, locality);

    cout << "Enter State: ";
    getline(cin, state);

    cout << "Enter Country (2-letter code): ";
    getline(cin, country);

    cout << "Enter Email Address: ";
    getline(cin, emailAddress);
}

// Getter implementations
string CA::getCommonName() const {
    return commonName;
}

string CA::getOrganizationName() const {
    return organizationName;
}

string CA::getOrganizationalUnit() const {
    return organizationalUnit;
}

string CA::getLocality() const {
    return locality;
}

string CA::getState() const {
    return state;
}

string CA::getCountry() const {
    return country;
}

string CA::getEmailAddress() const {
    return emailAddress;
}

// Setter implementations
void CA::setCommonName(const string& cn) {
    commonName = cn;
}

void CA::setOrganizationName(const string& on) {
    organizationName = on;
}

void CA::setOrganizationalUnit(const string& ou) {
    organizationalUnit = ou;
}

void CA::setLocality(const string& loc) {
    locality = loc;
}

void CA::setState(const string& st) {
    state = st;
}

void CA::setCountry(const string& cou) {
    country = cou;
}

void CA::setEmailAddress(const string& email) {
    emailAddress = email;
}

// Method to display CA information
void CA::displayInfo() const {
    cout << "Common Name: " << commonName << endl;
    cout << "Organization Name: " << organizationName << endl;
    cout << "Organizational Unit: " << organizationalUnit << endl;
    cout << "Locality: " << locality << endl;
    cout << "State: " << state << endl;
    cout << "Country: " << country << endl;
    cout << "Email Address: " << emailAddress << endl;
}

// Method to generate a certificate (placeholder)
void CA::generateCertificate(const string& domain) {
    cout << "Generating certificate for domain: " << domain << endl;
    // Placeholder for actual certificate generation logic
}