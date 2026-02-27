#pragma once
#include "System.h"
#include <fstream>
#include <iostream>
#include <assert.h>

using namespace std;

EncInfo Sys::encrypt(const string& dir, const string& cert) {
    ifstream m(dir, ios::in | ios::binary);
    if (!m.is_open()) {
        cerr << "file open error" << endl;
        return EncInfo();
    }

    cout << "生成散列值..." << endl;
    bitset<160> sha1 = SHA1(m);
    m.close();

    cout << "生成 " << this->client.getID() << " 的签名..." << endl;
    ZZ s = this->client.sig.sig(ShaVal2ZZ(sha1));

    cout << "生成 128 比特的随机 AES 会话密钥 k..." << endl;
    Key k;
    randomkey(k);

    cout << "在 CBC 模式下用 AES 会话密钥加密信息 (m || s || cert)..." << endl;
    m.open(dir, ios::in | ios::binary);
    m.seekg(0, ios::end);
    int length = m.tellg();
    m.seekg(0, ios::beg);
    string mstr(length, '\0');
    m.read(&mstr[0], length);
    m.close();

    string sstr = ZZ2str(s);
    string certstr = this->client.getCertificate();

    // 拼接格式：原文 + \n$ + 签名 + \n + 证书
    string obj = mstr + "\n$" + sstr + "\n" + certstr;
    string c1 = vec2str(CBCEncryption(str2vec(obj), k));

    cout << "用接收方公钥加密 k..." << endl;
    ZZ kzz = Key2ZZ(k);

    // 修复 Bug：必须用接收方(Alice)证书里的公钥加密 AES 密钥，而不是发件人自己的
    Client temp_receiver("temp");
    temp_receiver.verifyCertificate(cert, ta);
    ZZ c2 = temp_receiver.sig.rsa.encrypt(kzz);

    EncInfo c;
    c.c1 = c1;
    c.c2 = c2;

    cout << "向接收方发送 c" << endl;
    return c;
}

void Sys::decrypt(EncInfo c, const string& dir) {
    cout << "用私钥解密 k..." << endl;
    ZZ kzz = this->client.sig.rsa.decrypt(c.c2);
    Key k;
    ZZ2Key(kzz, k);

    cout << "用 k 解密 c1..." << endl;
    string buf = vec2str(CBCDecryption(str2vec(c.c1), k));

    stringstream stream(buf);
    string mstr, sstr, cert;

    readMessage(stream, mstr);
    getline(stream, sstr);
    readCert(stream, cert);

    ofstream m(dir, ios::out | ios::binary);
    m << mstr;
    m.close();

    ifstream mopen(dir, ios::in | ios::binary);
    cout << "验证发件人证书..." << endl;
    if (!this->varify(cert)) {
        cout << "警告：证书验证失败！" << endl;
        return; // 证书不合法，直接终止
    }

    bitset<160> sha1 = SHA1(mopen);
    mopen.close();

    cout << "验证发件人签名..." << endl;
    bool is_valid = this->client.sig.ver(ShaVal2ZZ(sha1), str2ZZ(sstr));

    if (is_valid)
        cout << "SUCCESS: 签名验证通过，文件安全！" << endl;
    else
        cout << "ERROR: 签名验证失败，文件可能被篡改！" << endl;
}

void readMessage(stringstream& stream, string& m) {
    char ch;
    m = "";
    while (stream.get(ch)) {
        if (ch == '\n' && stream.peek() == '$') {
            stream.get();
            break;
        }
        else {
            m += ch;
        }
    }
}

void readCert(stringstream& stream, string& cert) {
    string temp;
    cert = "";
    while (getline(stream, temp)) {
        cert = cert + temp + "\n";
    }
}