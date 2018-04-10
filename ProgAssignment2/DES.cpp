
#include <vector>
#include <cstdlib>
#include "DES.h"
#include "des_utils.h"
#include <string>

using namespace std;

//Public
DES::DES() {
	subkeys = vector<BString>();
	setKey(GenRandomKey());
	setIV(BString(64, '0'));
	CBC = false;
}
DES::DES(BString IV, string KEY, bool CBC) {
	setIV(IV);
	setKey(KEY);
	subkeys = vector<BString>();
}
void DES::setKey(string KHex) {
	/**
	*	Sets the given string of Hexadecimal characters and
	*	converts it to a binary string and sets that binary string as
	*	the current key
	**/
	KEY =  BString::HextoBinary(KHex);
}
void DES::setCBC(bool cbc) {
	CBC = cbc;
}
string DES::GenRandomKey() {
	/**
	*	Generates a random string with only 16 Hexadecimal character.
	**/
	string K = "";
	for (size_t i = 0; i < 16; i++) {
		size_t r = rand() % 16;
		if (r < 10) {
			K += r + '0';
		}
		else {
			K += (r-10) + 'A';
		}
	}
	return K;
}
string DES::Encrypt(string P) {
	/**
	*	Encrypts plaintext P with current KEY and IV
	**/
	string cipher="";
	GenSubKeys();
	//BString r;
	BString PHex = BString::TexttoHex(P);
	BString Plain = BString( PHex );

	size_t missing = Plain.size() % 64;
	if (missing != 0) {
		Plain =  Plain + BString(64 - missing,'0' );
	}
	//Seperates the plaintest into blocks
	vector<BString>Blocks = Plain.Split(Plain.size() / 64);

	//CBC part of DES. Chaining each each block to its previous
	for (size_t i = 0; i < Blocks.size(); i++) {
		//performing the encoding prossess on the current block
		if (CBC) {
			if (i == 1) {
				Blocks[i] = Blocks[i] ^ IV;
			}
			else {
				Blocks[i] = Blocks[i] ^ Blocks[i - 1];
			}
			Blocks[i] = encode(Blocks[i]);

		} else{
			Blocks[i] = encode(Blocks[i]);
		}
	}
	//converting block to string representation
	vector<BString>::const_iterator itr;
	for (itr = Blocks.begin(); itr != Blocks.end(); ++itr) {
		cipher += BString::BinarytoHex(*itr);
	}
	return cipher;
}
string DES::Decrypt(string C) {
	/**
	*	Decrypts cipher text C with current KEY and IV
	**/
	BString CHex = BString::TexttoHex(C);
	BString Cipher = BString(CHex);

	//spliting the cipher text into 64bit long blocks
	vector<BString>Blocks = Cipher.Split(Cipher.size() / 64);
	vector<BString>PBlocks = Blocks;
	//CBC part of DES. Chaining each each block to its previous
	for (size_t i = 0; i < Blocks.size(); i++) {
		//performing the encoding prossess on the current block
		if (CBC) {
			PBlocks[i] = decode(Blocks[i]);
			if (i == 0) {
				PBlocks[i] = PBlocks[i] ^ IV;
			}
			else {
				PBlocks[i] = PBlocks[i] ^ Blocks[i - 1];
			}
		}
		else {
			PBlocks[i] = decode(Blocks[i]);
		}
	}
	//converting block to string representation
	string plain = "";
	vector<BString>::const_iterator itr;
	for (itr = PBlocks.begin(); itr != PBlocks.end(); ++itr) {
		plain += BString::BinarytoHex(*itr);
	}
	return BString::HextoText(plain);
}
void DES::setIV(BString iv) { IV = iv; }
string DES::getIV()const {
	/**
	*	returns current Initiazation Value in Hexadecimal
	**/
	return BString::BinarytoHex(IV);
}
string DES::getKEY()const {
	/**
	*	returns current Key in Hexadecimal
	**/
	return BString::BinarytoHex(KEY);
}
//Private
void DES::GenSubKeys() {
	/**
	*	Generates all DES Sub Keys
	**/
	BString K56 = PCPermutate(KEY, PC1, 0);
	vector<BString> S = K56.Split(2);
	vector<BString> CDkey = vector<BString>();
	CDkey.push_back(S[0]);
	CDkey.push_back(S[1]);
	for (size_t i = 1; i <= 16; i++) {
		if (i <= 2 || i == 9 || i == 16) {
			//LeftShift(S[0], 1);
			S[0] = S[0] << 1;
			//LeftShift(S[1], 1);
			S[1] = S[1] << 1;
		}
		else {
			//LeftShift(S[0], 2);
			S[0] = S[0] << 2;
			//LeftShift(S[1], 2);
			S[1] = S[1] << 2;
		}
		CDkey.push_back(S[0]);
		CDkey.push_back(S[1]);
	}
	for (size_t i = 2; i < CDkey.size()-1; i+=2) {
		//BString temp = BSConcat(CDkey[i], CDkey[i+1]);
		subkeys.push_back(PCPermutate(CDkey[i] + CDkey[i+1], PC2, 1));
	}
}

BString DES::IFPermutate(BString bs, char* table) {
	/**
	*	Performes DES Permutation with table for either
	*	Intial permutation table or Final permutation table
	**/
	BString r = BString( 64,'0' );
	for (size_t i = 0; i < 64; i++) {
		size_t p = table[i];
		r[i] = bs[p-1];
	}
	return r;
}
BString DES::PPermuate(BString bs) {
	/*
		Does DES permutation on BS according to table P
	*/
	BString r = BString(32, '0');
	for (size_t i = 0; i < 32; i++) {
		size_t p = P[i];
		r[i] = bs[p-1];
	}
	return r;
}
BString DES::PCPermutate(BString bs, int* table, int num) {
	/**
	*	Does DES Permutation on a BinaryString with either PC-1 or PC-2 tables 
	**/
	int n;
	if (num == 0)
		n = 56;
	else
		n = 48;
	BString r = BString(n, '0');
	for (size_t i = 0; i < n; i++) {
		size_t p = table[i];
		r[i] = bs[p-1];
	}
	return r;
}
BString DES::Expand(BString bs) {
	/*
		Expands a 32 bit binarystring to 48bits
	*/
	BString Ebs = BString(48, '0');
	for (size_t i = 0; i < 48; i++) {
		size_t p = E[i];
		Ebs[i] = bs[p-1];
	}
	return Ebs;
}
BString DES::Sbox(BString bs, int n) {
	/**
	*	Performes a single DES Sbox calculation with SBox table n
	**/
	size_t col=0, row=0;
	//calculating row value
	col = bs[0] - '0';
	col << 1;
	col += bs[5] - '0';
	//calculating column value
	col = 0;
	for (size_t i = 1; i < 5; i++) {
		col += bs[i] - '0';
		col << 1;
	}
	//getting value from SBox_n
	size_t number = SBOXMAP[n][row * 16 + col];
	BString result = BString(4,'0');
	//converting to value to binarystring
	for (int i = 3; i >= 0; i--) {
		result[i] = (number % 2) + '0';
		number /= 2;
	}
	return result;
}
BString DES::Sboxes(BString RB ){
	/**
	*	Performes all SBox calculations on RB
	**/
	vector<BString> sections = RB.Split(8);
	//creating place for Sbox results
	BString Result = BString();
	//Sboxes
	for (size_t i = 0; i < 8; i++) {
		sections[i] = Sbox(sections[i],i);//B_i = S_i(B_i)
		Result = Result + sections[i];//Result = Result + B_i
	}
	return Result;
}
BString DES::encode(BString b) {
	//Inital Permutation
	b = IFPermutate(b, IP);
	//LR[0]: Left, LR[1]:Right
	//spliting b in half
	vector<BString> LR = b.Split(2);
	BString L, R;
	//DES rounds
	for (size_t i = 0; i < 16; i++) {
		LR = DESRound(LR[0], LR[1], i);
	}
	//Final Permutation
	return IFPermutate( LR[1] + LR[0] ,FP);
}
vector<BString> DES::DESRound(BString L, BString R, size_t key) {
	/**
		Performes one round of DES on L,R with subkey_key
		key is an index in subkeys
	*/
	//creating a value to hold result
	vector<BString> Result = vector<BString>(2,BString());
	//swaping L and R
	BString temp = R;
	R = L ^ f(R, subkeys[key]);	//R_n = L_n-1 ^ f(R_n-1,k_n)
	L = temp;
	//placeing L_n and R_n 
	Result[0] = L;
	Result[1] = R;

	return Result;
}
BString DES::decode(BString b) {
	//Initial Permuation on b
	b = IFPermutate(b, IP);
	//spliting b in two
	vector<BString> LR = b.Split(2);
	//DES rounds
	for (int i = 15; i >= 0; i--) {
		LR = DESRound(LR[0], LR[1], i);
	}
	//Final Permutations
	return IFPermutate(LR[1] + LR[0], FP);
}
///Static methods
BString DES::f(BString R, BString k) {
	//explanding 32 bit to 48bits via expland table
	R = Expand(R);
	//XORing E(R) with k
	BString r = R ^ k;
	//spliting r in to 8 sections
	vector<BString> sections = r.Split(8);
	//storing sbox results
	BString Result = Sboxes(r);
	//Permutation Result with table P
	Result = PPermuate(Result);

	return Result;
}

bool DES::Check(string k) {
	/*
		Checks if the entered string is valid for DES KEY or IV
	*/
	if (k.size() == 16) {
		for (string::const_iterator itr = k.begin();
			itr != k.end(); ++itr) {
			//if any character in Hexstring is not a Hex character
			//returns false
			if (!((*itr >= '0' && *itr <= '9')	||
				(*itr >= 'A' && *itr <= 'F')||
				(*itr >= 'a' && *itr <= 'f'))) {
				return false;
			}
		}
		return true;
	}
	return false;
}