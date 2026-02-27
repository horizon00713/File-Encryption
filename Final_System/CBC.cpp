#include "CBC.h"

using namespace std;

vector<char> IV;

vector<char> XOR(vector<char> a, vector<char> b)
{
	int l = a.size();
	if (l != b.size())
	{
		cout << "XOR error" << endl;
	}
	vector<char> res(l);
	for (int i = 0; i < l; i++)
	{
		res[i] = a[i] ^ b[i];
	}
	return res;
}

vector<char> randStr()
{
	vector<char> res;
	srand(time(NULL));
	for (int i = 0; i < 16; i++)
		res.push_back(rand() % 128);
	return res;
}

vector<char> CBCEncryption(vector<char> message, Key seed)
{
	vector<char> res;
	res = message;
	int len = res.size();
	char is_ext = 0;
	if (len % 16 != 0)
	{
		is_ext = 1;
		int ext = 16 - len % 16 - 1;
		for (int i = 1; i <= ext; i++)
			res.push_back(0);
		res.push_back((char)ext);
	}

	cout << "Use random IV? (1/0)" << endl;
	bool flag;
	cin >> flag;
	if (flag)
		IV = randStr();
	else
		IV = vector<char>(16, 0);

	vector<char> y_pre = IV;
	vector<char> y_cur(16);
	int n = res.size() / 16;
	vector<char> x_cur(16);

	for (int i = 1; i <= n; i++)
	{
		for (int j = 0; j < 16; j++)
			x_cur[j] = res[(i - 1) * 16 + j];

		x_cur = XOR(x_cur, y_pre);
		y_cur = AES(x_cur, seed);

		// The Soul of CBC Mode: Update the chain
		y_pre = y_cur;

		for (int j = 0; j < 16; j++)
		{
			res[(i - 1) * 16 + j] = y_cur[j];
		}
	}
	res.push_back(is_ext);
	return res;
}

vector<char> CBCDecryption(vector<char> code, Key seed)
{
	vector<char> res;
	res = code;
	if (res.empty()) return res;

	char is_ext = res.back();
	res.pop_back();

	vector<char> y_pre = IV;
	vector<char> y_cur(16);
	int n = res.size() / 16;
	vector<char> x_cur(16);

	for (int i = 1; i <= n; i++)
	{
		for (int j = 0; j < 16; j++)
			y_cur[j] = res[(i - 1) * 16 + j];

		x_cur = AESInv(y_cur, seed);
		x_cur = XOR(x_cur, y_pre);

		// The Soul of CBC Mode: Update the chain
		y_pre = y_cur;

		for (int j = 0; j < 16; j++)
		{
			res[(i - 1) * 16 + j] = x_cur[j];
		}
	}

	if (is_ext)
	{
		if (!res.empty())
		{
			int ext = (unsigned char)res.back();
			res.pop_back();

			// Ultimate Safety Valve: Prevent deleting the whole file if Key/IV is wrong
			if (ext > 16)
			{
				cout << "\n[!] WARNING: Padding error! Incorrect Key or IV. Output may be garbage." << endl;
				ext = 0;
			}

			while (ext > 0 && !res.empty())
			{
				res.pop_back();
				ext--;
			}
		}
	}
	return res;
}

string getIV()
{
	string res;
	int len = IV.size();
	for (int i = 0; i < len; i++)
	{
		res.push_back(IV[i]);
	}
	return res;
}

void setIV(string s)
{
	IV.clear();
	int len = s.length();
	for (int i = 0; i < len; i++)
	{
		IV.push_back(s[i]);
	}
}