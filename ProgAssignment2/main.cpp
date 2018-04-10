
#include <iostream>
#include <fstream>
#include "DES.h"
#include <string>
#include "BinaryString.h"
//#include <openssl\des.h>

using namespace std;

void test1() {
	//testing convertion functions
	cout << BString::BinarytoHex(BString(4,'1') ) << endl;
	cout << BString::HextoBinary("153746") << endl;
	cout << BString::BinarytoHex(BString::HextoBinary("153746") ) << endl;
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
	ofstream outfile;
	outfile.open("DES_OUT.txt", fstream::out);
	if (outfile.is_open()) {
		for (size_t i = 0; i < 3; i++) {
			tests[i].setCBC(true);
			tests[i].setKey(keys[i]);
			tests[i].setIV(IVs[i]);
			string E = tests[i].Encrypt(input[i]);
			string D = tests[i].Decrypt(E);
			if (E == truth[i]) {
				outfile << "Test " << i << ": Passed!" << endl;
			}
			else {
				outfile << "Test " << i << ": Failed." << endl;
			}
			outfile << "\t  E-OutHex: " << E << endl;
			outfile << "\t  D-OutHex: " << D << endl;
			outfile << "\t     Truth: " << truth[i] << endl;
			outfile << "\tD-OutPlain: " << BString::HextoText(D) << endl;;
			outfile << "\t       KEY: " << tests[i].getKEY() << endl;
			outfile << "\t        IV: " << tests[i].getIV() << endl;
		}
		outfile.close();
	}
}
void userinput() {
	cout << "DES-CBC Encryption" << endl;
	cout << "------------------------------" << endl;
	cout << "Preform Encryption(0) or Decryption(1)?" << endl;
	bool responce;
	cin >> responce;
	cout << "Use CBC mode: false(0) : True(1)" << endl;
	bool cbc;
	cin >> cbc;
	bool valid = 0;
	string Key, IV;
	while (!valid) {
		cout << "Enter (In Hex)Key: " << endl;
		cin >> Key;
		cout << "Enter (In Hex)IV: " << endl;
		cin >> IV;
		if (!DES::Check(Key)) {
			cout << "invalid Key\nMust be 16 Hex character long" << endl;
		}
		if (!DES::Check(IV)) {
			cout << "Invalid IV\nMust be 16 Hex character long" << endl;
		}
		else {
			valid = 1;
		}
	}
	cout << "Enter File with " << (responce ? "Cipher Text" : "Plain Text") << endl;
	string name;
	cin >> name;
	fstream in;
	in.open(name, fstream::in);
	string input = "";
	if (in.is_open()) {
		string line;
		while (!in.eof()) {
			in >> line;
			input += line;
		}
		in.close();
	}
	else {
		cout << "cannnot open file: " << name << endl;
		return;
	}
	DES user = DES(IV,Key,cbc);
	ofstream outfile;
	outfile.open("DES_OUT.txt", fstream::out);
	if (!responce) {
		outfile << user.Encrypt(input);
		
	}
	else {
		outfile << user.Decrypt(input);
	}
	outfile.close();
	cout << "Answer: was output to File \"DES-Out.txt\" " << endl;
}
int main() {
	test();
	//test1();
	return 0;
}