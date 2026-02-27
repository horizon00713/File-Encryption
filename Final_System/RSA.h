#ifndef RSA_H
#define RSA_H
#include<NTL/ZZ.h>
using namespace NTL;

const int PRIME_LEN1 = 512;
const int PRIME_LEN2 = 1024;

// 就是少了下面这个极其重要的结构体
struct Public_key
{
	ZZ n;
	ZZ b;
};

class RSA {
public:
	Public_key pub;
public:
	RSA();
	RSA(const RSA&);
	void operator=(const RSA&);
	void setPublicKey(Public_key);
	void GenerateKey(int l = PRIME_LEN1);
	ZZ encrypt(ZZ) const;
	ZZ decrypt(ZZ) const;
	Public_key GetPublicKey() const { return this->key.pub; } // 修复缺少 const 的报错
private:
	struct Private_key
	{
		ZZ p;
		ZZ q;
		ZZ a;
	};
	struct Key
	{
		Public_key pub;
		Private_key pri;
	};
	Key key;
};

#endif