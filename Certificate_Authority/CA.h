#pragma once

#include <string>
#include <vector>

using namespace std;

class CA {
private:
    string commonName;
    string organizationName;
    string organizationalUnit;
    string locality;
    string state;
    string country;
    string emailAddress;

public:
    // Constructor with parameters
    CA(const string& cn, const string& on, const string& ou,
       const string& loc, const string& st, const string& cou,
       const string& email);

    // Constructor for user input
    CA();

    // Getters
    string getCommonName() const;
    string getOrganizationName() const;
    string getOrganizationalUnit() const;
    string getLocality() const;
    string getState() const;
    string getCountry() const;
    string getEmailAddress() const;

    // Setters
    void setCommonName(const string& cn);
    void setOrganizationName(const string& on);
    void setOrganizationalUnit(const string& ou);
    void setLocality(const string& loc);
    void setState(const string& st);
    void setCountry(const string& cou);
    void setEmailAddress(const string& email);

    // Method to display CA information
    void displayInfo() const;

    // Method to generate a certificate (placeholder)
    void generateCertificate(const string& domain);
};