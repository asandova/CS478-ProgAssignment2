DES Encryption Algorithm

Compile:
	On Linux systems
		the program requires C++ 11 to work(Does work on the Linux systems on campus)
		Use provided makefile
	To compile
		type "make" in terminal in directory with the makefile
		The make file will then output executable file des

Run:
	To run the program
	type ./des in the terminal
	The program will then prompt
	
	The program will ask if you want to do Encryption or Decryption
	use CBC or EBC mode
	Ask for a Key and IV(in in CBC mode)
		For the Key you have the option to choose a KEY or use a randomly generated one
	The KEY and IV must be a Hexadecimal value of 16 characters
	
	The program will then ask for a input file
	This file should contain just the cipher or plain text
		Note: the file can contain Hex or Ascii text for the cipher or plain text
		This will determine the output format (i.e. input text is in hex then output is hex).
	
	The program will then Output it's Answer to a File "DES-OUT.txt"
	This file will contain the cipher(for Encryption) or plain(for Decryption) text 
	and the IV(will not show up if in EBC mode) and Key used
	
	After output the program will exit