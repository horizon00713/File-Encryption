#ifndef UTIL_H
#define UTIL_H
#include <string>
#include <vector>
#include <NTL/ZZ.h>
#include "AES.h" 
#include <bitset>

using namespace std;
using namespace NTL;

string vec2str(vector<char> v);
vector<char> str2vec(const string& s);
ZZ Key2ZZ(const Key& k);
void ZZ2Key(const ZZ& zz, Key& k);
void randomkey(Key& k);
ZZ ShaVal2ZZ(const bitset<160>& sha1);

#endif#pragma once
