
#include <iostream>
#include <fstream>
#include "DES.h"
#include <string>
#include "BinaryString.h"
//#include <openssl\des.h>

using namespace std;

void test1() {

	DES test = DES("3835383439343739","54455354494E4731",false);
	cout << "--------------------------------------" << endl;
	cout << test.Encrypt("Testing DES Encryption",false) << endl;
	cout << "--------------------------------------" << endl;
	cout << BString::HextoText(test.Decrypt("3631A23C1FD0F0346E080CA75FFD1BD747E7C1AE97B5532E",true)) << endl;
}
//used to set
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
		"25BFADF6893268CB64EB99F3E05CDF79",
		"253E43DD2B5C6548D9F5E0226320DA06FB9D962AC0D3C336",
		"9E70DCEC6203F1524A2D57E33807EB42941172D3E66FC295AF38F05B1C7AB3EB"
	};

	vector<DES> tests = vector<DES>(3,DES());
	ofstream outfile;
	outfile.open("DES_OUT.txt", fstream::out);
	if (outfile.is_open()) {
		for (size_t i = 0; i < 3; i++) {
			tests[i].setCBC(true);
			tests[i].setKey(keys[i]);
			tests[i].setIV(IVs[i]);
			string E = tests[i].Encrypt(input[i], false);
			string D = tests[i].Decrypt(E,true);
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
		cout << "Test case Results were outputed to DES_OUT.txt" << endl;
	}
	else
	{
		cout << "error opening out file" << endl;
	}
}
void userinput() {
	cout << "DES Encryption" << endl;
	cout << "------------------------------" << endl;
	cout << "Preform Encryption(0) or Decryption(1)?" << endl;
	bool responce;
	cin >> responce;
	cout << "Use CBC mode?: false(0) : True(1)" << endl;
	bool cbc, random;
	cin >> cbc;
	cout << "Use Random Key? False(0) : True(1)" << endl;
	cin >> random;
	bool validKey = 0,validIV = 0;
	string Key, IV= "";
	if (!random) {
		while (!validKey) {
			cout << "Enter (In Hex)Key: " << endl;
			cin >> Key;
			if (!DES::Check(Key)) {
				cout << "invalid Key\nMust be 16 Hex character long" << endl;
			}
			else {
				validKey = 1;
			}
		}
	}
	else {
		Key = DES::GenRandomKey();
	}
	if (cbc) {
		while (!validIV) {
			cout << "Enter (In Hex)IV: " << endl;
			cin >> IV;
			if (!DES::Check(IV)) {
				cout << "Invalid IV\nMust be 16 Hex character long" << endl;
			}
			else {
				validIV = 1;
			}
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
	outfile.open("DES-OUT.txt", fstream::out);
	outfile << "Key: " << Key << endl;
	if (cbc) {
		outfile << "IV: " << IV << endl;
	}

	if (!responce) {

		outfile << user.Encrypt(input,false);
	}
	else {
		outfile << user.Decrypt(input,true);
	}
	outfile.close();
	cout << "Answer: was output to File \"DES-Out.txt\" " << endl;
}

int main() {
	//test();
	//test1();
	userinput();
	return 0;
}