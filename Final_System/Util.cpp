#include "Util.h"
#include <time.h>

string vec2str(vector<char> v) {
    return string(v.begin(), v.end());
}

vector<char> str2vec(const string& s) {
    return vector<char>(s.begin(), s.end());
}

ZZ Key2ZZ(const Key& k) {
    ZZ res = ZZ(0);
    for (int i = 0; i < 16; i++) {
        res = (res << 8) + (unsigned char)k[i];
    }
    return res;
}

void ZZ2Key(const ZZ& zz, Key& k) {
    ZZ temp = zz;
    for (int i = 15; i >= 0; i--) {
        k[i] = to_int(temp & ZZ(0xFF));
        temp >>= 8;
    }
}

void randomkey(Key& k) {
    srand(time(NULL));
    for (int i = 0; i < 16; i++) {
        k[i] = rand() % 256;
    }
}

ZZ ShaVal2ZZ(const bitset<160>& sha1) {
    ZZ res = ZZ(0);
    string s = sha1.to_string();
    for (char c : s) {
        res = (res << 1) + (c - '0');
    }
    return res;
}