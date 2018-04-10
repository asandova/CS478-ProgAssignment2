
#include <iostream>
#include "DES.h"
#include <string>
#include "BinaryString.h"
#include <openssl\des.h>

using namespace std;

void test1() {
	cout << BString::BinarytoHex(BString(4,'1') ) << endl;
	cout << BString::HextoBinary("0123456789ABCDEF") << endl;
	cout << BString::BinarytoHex(BString::HextoBinary("0123456789ABCDEF") ) << endl;
}

void test() {
	string input[] = {
		"This is a Test",
		"Testing DES Encryption",
		"CS478 - Computer Security"
	};
	string keys[] = {
		"54455354494E4731",
		"4353343738434f4d",
		"4445535445535431"
	};
	string IVs[] = {
		"3835383439343739",
		"DA39A3EE5E6B4B0D",
		"1537465ADCBA5FCC"
	};
	string truth[] = {
		"7F08D75379C9ADAC909094A5088E01DA",
		"2A36C8D4422E8D97141581F2C21FB3D2615D17B398E143EC",
		"3923245A60E672626CF8CB7C1C46E592FBD999C575E52F73644E63165AD7638D"
	};
	vector<DES> tests = vector<DES>(3,DES());
	for (size_t i = 0; i < 3; i++) {
		tests[i].setKey(keys[i]);
		tests[i].setIV(IVs[i]);
		string E = tests[i].Encrypt(input[i]);
		string D = tests[i].Decrypt(E);
		if (E == truth[i]) {
			cout << "Test " << i << ": Passed!" << endl;
		}
		else {
			cout << "Test " << i << ": Failed." << endl;
		}
		cout << "\tE-Output: " << E << endl;
		cout << "\tD-Output: " << D << endl;
		cout << "\t  Truth : " << truth[i] << endl;
		cout << "\t     KEY: " << tests[i].getKEY() << endl;
		cout << "\t      IV: " << tests[i].getIV() << endl;
	}
}

int main() {
	test();
	//test1();
	return 0;
}