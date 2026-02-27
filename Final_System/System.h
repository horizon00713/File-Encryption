#ifndef SYSTEM_H
#define SYSTEM_H
#include "Certificate.h"
#include "AES.h"
#include "CBC.h"
#include "SHA.h"
#include "Util.h"
#include <string>

using namespace std;

struct EncInfo {
    string c1;
    ZZ c2;
};

class Sys {
public:
    Client client;
    const TA& ta;

    Sys(Client c, const TA& t) : client(c), ta(t) {}

    EncInfo encrypt(const string& dir, const string& cert);
    void decrypt(EncInfo c, const string& dir);
    bool varify(const string& cert) { return client.verifyCertificate(cert, ta); }
};

void readMessage(stringstream& stream, string& m);
void readCert(stringstream& stream, string& cert);

#endif#pragma once
