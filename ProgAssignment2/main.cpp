
#include <iostream>
#include "DES.h"
#include <string>
#include "BinaryString.h"
#include <openssl\des.h>

using namespace std;
/*
void test1() {
	cout << "Testing:" << endl;
	cout << "\tHex: " << BString::TexttoHex("Testing") << endl;
	cout << "\tText: " << BString::HextoText(BString::TexttoHex("Testing")) << endl;
	cout << "\tBinary: " << BString::HextoBinary(BString::TexttoHex("Testing")) << endl;
	cout << "\tHex: " << BString::BinarytoHex(BString::HextoBinary(BString::TexttoHex("Testing"))) << endl;
	cout << "15:" << BString::BinarytoHex(BString(8,'1'));
}*/

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
		"1537465ADCbA5FCC"
	};
	string truth[] = {
		"66776A5855336E4A7261794751485973652F757A4C513D3D",
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
		cout << "\tEOutput: " << E << endl;
		cout << "\tDOutput: " << D << endl;
		cout << "\t Truth : " << truth[i] << endl;
	}
}

int main() {
	test();
	//test1();
	return 0;
}