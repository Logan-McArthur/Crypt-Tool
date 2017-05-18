// Logan McArthur
// CSS 337
// Encryption Tool
// February 21, 2017



#include "cryptopp\cryptlib.h"
#include "cryptopp\osrng.h"
#include "cryptopp\pwdbased.h"
#include "cryptopp\hex.h"
#include "cryptopp\sha3.h"
#include "cryptopp\filters.h"
#include "cryptopp\files.h"
#include "cryptopp\modes.h"
#include "cryptopp\base64.h"
#include "cryptopp\winpipes.h"

#include <fstream>
#include <iostream>
#include <string>

#include <boost\program_options.hpp>

using namespace std;
using namespace CryptoPP;

void printText(string rawText, const char* prefix);
void printKey(SecByteBlock& key, const char* prefix);

string encrypt(SecByteBlock& encryptionKey, byte iv[], int ivLength, const char plaintext[], int textLength);
string decrypt(SecByteBlock& decryptionKey, byte iv[], int ivLength, string cipherText);

bool verifyHMAC(SecByteBlock& key, string mac, string cipherText);

void readFile(string fileName, SecByteBlock& salt, string& hmac, byte iv[], string& cipherText);
void readStream(istream& input, SecByteBlock& salt, string& hmac, byte iv[], string& cipherText);
void generateKeys(string, string, string, SecByteBlock&, SecByteBlock&, SecByteBlock&, SecByteBlock&);

template <class T>
int performHmacForKey(SecByteBlock& key, SecByteBlock& resultKey, const char* saltInput, int saltSize);

void encryptFile(string password, string inputFileName, string outputFileName, bool streamBased);
void decryptFile(string password, string inputFileName, string outputFileName, bool streamBased);

#define SALT_SIZE 32
#define MASTER_KEY_SIZE 64
#define KDF_ITERATIONS 100000
#define SUB_KEY_SIZE 32
#define ENCRYPTION_KEY_SALT "EncryptionKeySalt"
#define HMAC_SALT "HMACSalt to be used"



namespace po = boost::program_options;

// Arguments: 
// Command line flags: -d (decrypt) -p
//
int main(int argc, char* argv[])
{

	bool streamBased = false;
	bool encrypt = false;

	po::options_description desc("Allowed options");
	desc.add_options()("help", "produce help message")
		("decrypt", po::value<bool>(), "decrypt the incoming file")
		("password", po::value<std::string>(), "password to use as the key")
		("stream", "operate the utility with streams");

	po::variables_map vm;
	po::store(po::parse_command_line(argc, argv, desc), vm);
	po::notify(vm);

	if (vm.count("help"))
	{
		cout << desc << endl;
		return 1;
	}

	/*if (vm.count("stream"))
	{
		streamBased = vm["stream"].as<bool>();
	}*/
	streamBased = vm.count("stream");
	

	//try {
	//	TCLAP::CmdLine cmd("Command description message", ' ', "0.9");

	//	TCLAP::SwitchArg decryption("d","decrypt","Decrypt the input file and output to stream", false);
	//	TCLAP::SwitchArg stream("s", "stream", "Operate the encryption utility in a stream", false);

	//	cmd.parse(argc, argv);
	//	encrypt = decryption.getValue();
	//	streamBased = stream.getValue();
	//}
	//catch (TCLAP::ArgException &e)
	//{
	//	cerr << "Error parsing command line arguments" << endl;
	//}
	if (streamBased)
	{
		if (vm.count("decrypt"))
		{
			decryptFile(vm["password"].as<std::string>(), "", "", true);
		}
		else
		{
			encryptFile(vm["password"].as<std::string>(), "", "", true);
		}
	}
	else
	{
		char choice;
		string password;// = "Password";
		string inputFile;// = "plaintext";
		string outputFile;// = "outputFile.txt";

		cout << "What file do you want to read? ";
		cin >> inputFile;

		cout << "Do you want to (e)ncrypt or (d)ecrypt? ";
		cin >> choice;

		cout << "What password do you want to use? ";
		cin >> password;

		cout << "What file do you want to output to? ";
		cin >> outputFile;
		if (choice == 'e')
			//encryptFile(password, inputFile, outputFile);
			encrypt = true;
		else if (choice == 'd')
			//decryptFile(password, inputFile, outputFile);
			encrypt = false;
	}

	
	
	//if (choice == 'e')
	//	encryptFile(password, inputFile, outputFile);
	//else if (choice == 'd')
	//	decryptFile(password, inputFile, outputFile);
	return 0;
}

void decryptFile(string password, string inputFileName, string outputFileName, bool streamBased)
{
	string encryptSalt = ENCRYPTION_KEY_SALT;
	string hmacSalt = HMAC_SALT;
	
	SecByteBlock salt(SALT_SIZE);
	SecByteBlock masterKey(MASTER_KEY_SIZE);
	SecByteBlock encryptionKey(SUB_KEY_SIZE);
	SecByteBlock hmacKey(SUB_KEY_SIZE);
	
	string hmac;
	byte iv[AES::BLOCKSIZE];
	string cipherText;
	
	if (streamBased)
	{
		readStream(cin, salt, hmac, iv, cipherText);
	}
	else
	{
		readFile(inputFileName, salt, hmac, iv, cipherText);

	}
	
	//cout << "Encrypted ciphertext: " << cipherText << endl;
	
	generateKeys(password, encryptSalt, hmacSalt, salt, masterKey, encryptionKey, hmacKey);
	
	if (verifyHMAC(hmacKey, hmac, cipherText))
	{
		// Good
		cerr << "Ciphertext verified according to HMAC." << endl;
	}
	else
	{
		// Bad
		cerr << "Ciphertext could not be verified. Aborting." << endl;
		return;
	}
	
	string recoveredText = decrypt(encryptionKey, iv, AES::BLOCKSIZE, cipherText);

	if (streamBased)
	{
		cout << recoveredText << endl;
	}
	else
	{
		StringSource fileOutput(recoveredText, true, new FileSink(outputFileName.c_str()));
	}
	
	// Would normally be commented out
	//cout << "Recovered Text: " << recoveredText << endl;
}

void encryptFile(string password, string inputFileName, string outputFileName, bool streamBased)
{
	string encryptSalt = ENCRYPTION_KEY_SALT;
	string hmacSalt = HMAC_SALT;
	
	SecByteBlock salt(SALT_SIZE);
	SecByteBlock masterKey(MASTER_KEY_SIZE);
	SecByteBlock encryptionKey(SUB_KEY_SIZE);
	SecByteBlock hmacKey(SUB_KEY_SIZE);
	
	// Randomly generate salt
	OS_GenerateRandomBlock(false, salt, salt.size());
	
//	printKey(salt, "Salt: ");
	
	generateKeys(password, encryptSalt, hmacSalt, salt, masterKey, encryptionKey, hmacKey);

//	printKey(masterKey, "Master Key: ");
//	printKey(encryptionKey, "Encryption Key: ");
//	printKey(hmacKey, "HMAC Key: ");

	// Now on to encryption
	byte iv[AES::BLOCKSIZE];
	OS_GenerateRandomBlock(false, iv, AES::BLOCKSIZE);

	string plainText;
	
	// Encryption

	if (streamBased)
	{
		FileSource inputStream(cin, true, new StringSink(plainText));
	}
	else
	{
		FileSource inputFile(inputFileName.c_str(), true, new StringSink(plainText));
	}

	//cout << "Plaintext: " << plainText << endl;
	
	string cipherText = encrypt(encryptionKey, iv, AES::BLOCKSIZE, plainText.c_str(), plainText.size());
	
	//cout << "Ciphertext: " << cipherText << endl;
	string hmacOfEncryptedText;
	
	// HMAC the encrypted text
	HMAC<SHA3_512> encryptedTextHMAC(hmacKey, hmacKey.size());
	StringSource encTextHmac(cipherText, true, new HashFilter(encryptedTextHMAC,
			new StringSink(hmacOfEncryptedText)
		)
	);
	
	//printText(hmacOfEncryptedText, "Hmac of Cipher: ");
	
	
	verifyHMAC(hmacKey, hmacOfEncryptedText, cipherText);

	
	string finalSalt;
	string finalHMAC;
	string finalIV;
	string finalCipher;

	ArraySource aS(salt, salt.size(), true, new Base64Encoder(new StringSink(finalSalt), false));
	StringSource fH(hmacOfEncryptedText, true, new Base64Encoder(new StringSink(finalHMAC), false));
	ArraySource fI(iv, AES::BLOCKSIZE, true, new Base64Encoder(new StringSink(finalIV), false));
	StringSource fC(cipherText, true, new Base64Encoder(new StringSink(finalCipher), false));



	if (streamBased)
	{
		cout << finalSalt << endl;
		cout << finalHMAC << endl;
		cout << finalIV << endl;
		cout << finalCipher << endl;
	}
	else
	{
		ofstream file;
		file.open(outputFileName.c_str());

		file << finalSalt << endl;
		file << finalHMAC << endl;
		file << finalIV << endl;
		file << finalCipher << endl;

		file.close();
	}

	
}

string encrypt(SecByteBlock& encryptionKey, byte iv[], int ivLength, const char plainText[], int textLength)
{
	CBC_Mode<AES>::Encryption cbcEncryptor;
	cbcEncryptor.SetKeyWithIV(encryptionKey, encryptionKey.size(), iv);

	string cipherText;
	StringSource encryptionSource( plainText, 
			true, new StreamTransformationFilter( cbcEncryptor, new StringSink(cipherText)
		)
	); // StringSource
	
	return cipherText;
}

string decrypt(SecByteBlock& decryptionKey, byte iv[], int ivLength, string cipherText)
{
	CBC_Mode<AES>::Decryption cbcDecryptor;
	cbcDecryptor.SetKeyWithIV(decryptionKey, decryptionKey.size(), iv);
	
	string recoveredText;
	StringSource decryptionSource(cipherText, 
			true, new StreamTransformationFilter( cbcDecryptor, new StringSink(recoveredText)
		)
	);
	return recoveredText;
}

void readFile(string fileName, SecByteBlock& salt, string& hmac, byte iv[], string& cipherText)
{
	ifstream input(fileName.c_str());
	readStream(input, salt, hmac, iv, cipherText);
	input.close();
	//string text;
	//
	//getline(input, text);
	//StringSource sS(text, true, new Base64Decoder(new ArraySink(salt,salt.size())));
	//
	////printKey(salt, "Recovered salt: ");
	//
	//string hmacEncoded;
	//getline(input, hmacEncoded);
	//StringSource sH(hmacEncoded, true, new Base64Decoder(new StringSink(hmac)));
	//
	////printText(hmac, "Recovered hmac: ");
	//
	//string encodedIV;
	//getline(input, encodedIV);
	//StringSource sI(encodedIV, true, new Base64Decoder(new ArraySink(iv,AES::BLOCKSIZE)));
	//
	//string cipherEncoded;
	//getline(input, cipherEncoded);
	//StringSource sC(cipherEncoded, true, new Base64Decoder(new StringSink(cipherText)));
	
	//printText(cipherText, "Recovered cipher: ");
	
	
}

void readStream(istream& input, SecByteBlock& salt, string& hmac, byte iv[], string& cipherText)
{
	string text;

	getline(input, text);
	StringSource sS(text, true, new Base64Decoder(new ArraySink(salt, salt.size())));

	//printKey(salt, "Recovered salt: ");

	string hmacEncoded;
	getline(input, hmacEncoded);
	StringSource sH(hmacEncoded, true, new Base64Decoder(new StringSink(hmac)));

	//printText(hmac, "Recovered hmac: ");

	string encodedIV;
	getline(input, encodedIV);
	StringSource sI(encodedIV, true, new Base64Decoder(new ArraySink(iv, AES::BLOCKSIZE)));

	string cipherEncoded;
	getline(input, cipherEncoded);
	StringSource sC(cipherEncoded, true, new Base64Decoder(new StringSink(cipherText)));

	//printText(cipherText, "Recovered cipher: ");
	

}

void generateKeys(string password, string encryptSalt, string hmacSalt, 
	SecByteBlock& salt, SecByteBlock& masterKey, SecByteBlock& encryptionKey, SecByteBlock& hmacKey)
{

	int iterations = KDF_ITERATIONS;
	PKCS5_PBKDF2_HMAC<SHA3_512> pbkdf;
	pbkdf.DeriveKey(
		masterKey, masterKey.size(), 0x00, 
		(byte*)password.data(), password.size(), 
		salt, salt.size(), iterations
	);

	performHmacForKey<SHA3_512>(masterKey, encryptionKey, encryptSalt.c_str(), encryptSalt.size());
	performHmacForKey<SHA3_512>(masterKey, hmacKey, hmacSalt.c_str(), hmacSalt.size());
}

bool verifyHMAC(SecByteBlock& key, string mac, string cipherText)
{
	try {
		const int flags = HashVerificationFilter::THROW_EXCEPTION | HashVerificationFilter::HASH_AT_END;
	
		HMAC<SHA3_512> hmac(key, key.size());
	
		StringSource(cipherText + mac, true, 
			new HashVerificationFilter(hmac, NULL, flags)
		);
		return true;
	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		return false;
	}
	return false;
}


// A utility function to encode a raw text into hex and print with the passed
//	prefix
void printText(string rawText, const char* prefix)
{
	string encoded;
	StringSource ss( rawText, true, new HexEncoder(new StringSink(encoded) ) );
	cout << prefix << encoded << endl;

}


void printKey(SecByteBlock& key, const char* prefix)
{
	string keyText;
	ArraySource as(key, key.size(), true, new HexEncoder(new StringSink(keyText)));
	cout << prefix << keyText << endl;
}

template <class T>
int performHmacForKey(SecByteBlock& key, SecByteBlock& resultKey, const char* saltInput, int saltSize)
{
	HMAC<T> hmacEncryption(key, key.size());
	
	hmacEncryption.Update( (const byte *) saltInput, saltSize);
	hmacEncryption.TruncatedFinal(resultKey, resultKey.size());

	return 0;
}

