#ifndef DES_H
#define DES_H

#include <vector>
#include <string>
#include "BinaryString.h"

using namespace std;


class DES {
public:
	///implemented
	DES();
	///implemented
	DES(BString IV, string KEY, bool CBC);
	void setKey(string KHex);
	///implemented
	string GenRandomKey();

	string Encrypt(string P);

	string Decrypt(string C);
	///implemented
	void setCBC(bool cbc);
	///implemented
	void setIV(BString iv);
	///implemented
	string getIV()const;
	///implemented
	string getKEY()const;
	///implemented
	static bool Check(string k);
private:
	BString IV;
	BString KEY;//64bits
	vector<BString> subkeys;
	bool CBC;
	///implemented
	void GenSubKeys();
	BString encode(BString b);
	vector<BString> DESRound(BString L, BString R, size_t Key);
	BString decode(BString b);
	///implemented
	static BString IFPermutate(BString bs, char* table);
	///implemented
	static BString PPermuate(BString bs);
	///implemented
	static BString PCPermutate(BString bs, int* table,int num);
	///implemented
	static BString Expand(BString bs);
	///implemented
	static BString Sbox(BString bs,int n);
	///implemented
	static BString Sboxes(BString RB);
	///implemented
	static BString f(BString R, BString k);
};
#endif // !DES_H
