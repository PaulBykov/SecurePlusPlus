#include "Secure.h"

#include <iostream>
#include <fstream>
#include <iomanip>
#include <cstring>
#include <sstream>
#include <cstdint>
#include <sstream>
#include <vector>
#include <map>


#define ENCRYPTION_KEY 0x11
#define CRYPTED_PREFIX "_crypted"
#define DECRYPTED_PREFIX "_decrypted"

namespace Secure {

	std::map<std::string, std::pair<std::string, std::string>> alphabets = {
		{"eng", {"abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"}},
		{"rus" , {"абвгдеЄжзийклмнопрстуфхцчшщъыьэю€", "јЅ¬√ƒ≈®∆«»… ЋћЌќѕ–—“”‘’÷„ЎўЏџ№Ёёя"}}
	};

	// исключени€:

	class FileOpenException : public std::exception {
	public:
		FileOpenException(const std::string& fileName) : fileName_(fileName) {}

		virtual const char* what() const noexcept override {
			return ("Failed to open file: " + fileName_).c_str();
		}

	private:
		std::string fileName_;
	};

	class FileReadException : public std::exception {
	public:
		FileReadException(const std::string& fileName) : fileName_(fileName) {}

		virtual const char* what() const noexcept override {
			return ("Failed to read file: " + fileName_).c_str();
		}

	private:
		std::string fileName_;
	};

	class FileWriteException : public std::exception {
	public:
		FileWriteException(const std::string& fileName) : fileName_(fileName) {}

		virtual const char* what() const noexcept override {
			return ("Failed to write to file: " + fileName_).c_str();
		}

	private:
		std::string fileName_;
	};

	class LocalisationException {
	public:

		virtual const char* what() const noexcept {
			return ("Unknow Localisation!");
		}

	private:
		std::string fileName_;
	};

	// 2 костыл€ нужны дл€ fileEncrypt и fileDecrypt определ€ютс€ при binaryRead(), чтобы не увеличивать кол-во
	// аргументов этой функции сделал глобальными (btw пришлось бы их определ€ть в скопе 2-х методов, поэтому оправданно)
	std::streamsize size;
	char* in;


	// методы:


	void binaryRead(std::string& fileName, std::string& fileFormat) {

		std::ifstream inputFile(fileName + fileFormat, std::ios::binary | std::ios::ate);

		if (!inputFile.is_open()) {
			throw FileOpenException(fileName + fileFormat);
		}

		size = inputFile.tellg();
		inputFile.seekg(0, std::ios::beg);  // возвращаем указатель в начало файла

		in = new char[size]; // WARNING! ћб умный указатель будет лучше
		if (!inputFile.read(in, size)) {
			throw FileReadException(fileName + fileFormat);
		}

		inputFile.close();
	}

	void binaryWrite(std::string& fileName, std::string& fileFormat, std::string newFileName) {
		std::ofstream outputFile(newFileName, std::ios::binary);

		if (!outputFile.is_open()) {
			throw FileOpenException(newFileName + fileFormat);
		}

		if (!outputFile.write(in, size)) {
			throw FileWriteException(newFileName + fileFormat);
		}

		outputFile.close();
	}


	std::string getFileFormat(std::string& fileName) {
		// after this method fileName would contain only name of file (before ".")
		// returning value will become everything after "." (including dot)

		std::string fileFormat;

		for (int i = 0; i < fileName.size(); i++) {
			if (fileName[i] == *".") {
				for (int j = i; j < fileName.size(); j++) {
					fileFormat.push_back(fileName[j]); // записываем формат файла = точка и все после неЄ
				}
				fileName.erase(i); // удал€ем точку и до конца строки
			}
		}

		return fileFormat;
	}


	void fileEncrypt(std::string fileName, std::string newFileName) {

		std::string fileFormat = getFileFormat(fileName);

		if (newFileName == "")
			newFileName = fileName + CRYPTED_PREFIX + fileFormat;
		else
			newFileName += fileFormat;
		// т.к. им€ динамическое -> нельз€ поставить как по умолчанию


		binaryRead(fileName, fileFormat);

		for (int i = 0; i < size; i++) {
			in[i] = in[i] - ENCRYPTION_KEY;
		}

		binaryWrite(fileName, fileFormat, newFileName);

		delete[] in;
	}

	void fileDecrypt(std::string fileName, std::string newFileName) {

		std::string fileFormat = getFileFormat(fileName);

		if (newFileName == "")
			newFileName = fileName + DECRYPTED_PREFIX + fileFormat;
		else
			newFileName += fileFormat;
		// т.к. им€ динамическое -> нельз€ поставить по умолчанию, поэтому костыль

		binaryRead(fileName, fileFormat);

		for (int i = 0; i < size; i++) {
			in[i] = in[i] + ENCRYPTION_KEY;
		}

		binaryWrite(fileName, fileFormat, newFileName);

		delete[] in;
	}

	// зр€ € так писал, встроенные методы строк были бы круче, € чет уже не соображаю 
	// Ќјƒќ ƒЋя ÷≈«ј–я (салат)
	int index(char s1, std::string s2) { // возв. индекс первого вхождени€ s1 в s2
		for (int i = 0; i < s2.size(); i++) {
			if (s2[i] == s1) {
				return i;
			}
		}

		return -1;
	}

	std::string сaesarEncrypt(std::string text, int key, std::string localisation) {
		std::string alphabet;
		std::string alphabetCapitalized;
		std::string newText = text;

		if (!alphabets.count(localisation)) {
			throw LocalisationException();
		}

		alphabet = (alphabets[localisation]).first;
		alphabetCapitalized = (alphabets[localisation]).second;


		for (int i = 0; i < text.size(); i++) {
			int temp = index(text[i], alphabet);

			if (temp > -1) {
				newText[i] = alphabet[abs((index(text[i], alphabet) + key)) % alphabet.size()];
			}
			else if (index(text[i], alphabetCapitalized) > -1) {
				temp = index(text[i], alphabetCapitalized);
				newText[i] = alphabet[(abs(index(text[i], alphabet) + key)) % alphabet.size()];
			}

		}

		return newText;
	}

	std::string XOR(std::string text, char key) {
		std::string result = "";
		for (int i = 0; i < text.length(); i++) {
			result += char(text[i] ^ key);
		}
		return result;
	}

	std::string vigenereEncrypt(std::string plaintext, std::string key)
	{
		std::string ciphertext = "";
		int key_index = 0;
		for (char& c : plaintext)
		{
			if (isalpha(c))
			{
				int shift = tolower(key[key_index % key.length()]) - 'a';
				if (isupper(c))
				{
					ciphertext += (c - 'A' + shift) % 26 + 'A';
				}
				else
				{
					ciphertext += (c - 'a' + shift) % 26 + 'a';
				}
				key_index++;
			}
			else
			{
				ciphertext += c;
			}
		}
		return ciphertext;
	}

	std::string vigenereDecrypt(std::string ciphertext, std::string key)
	{
		std::string plaintext = "";
		int key_index = 0;
		for (char& c : ciphertext)
		{
			if (isalpha(c))
			{
				int shift = tolower(key[key_index % key.length()]) - 'a';
				if (isupper(c)) {
					plaintext += (c - 'A' - shift + 26) % 26 + 'A';
				}
				else
				{
					plaintext += (c - 'a' - shift + 26) % 26 + 'a';
				}
				key_index++;
			}
			else
			{
				plaintext += c;
			}
		}
		return plaintext;
	}

	// sha256:
	constexpr uint32_t ROTL(uint32_t x, uint32_t n) {
		return (x << n) | (x >> (32 - n));
	}

	constexpr uint32_t ROTR(uint32_t x, uint32_t n) {
		return (x >> n) | (x << (32 - n));
	}

	constexpr uint32_t SHR(uint32_t x, uint32_t n) {
		return x >> n;
	}

	constexpr uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) {
		return (x & y) ^ (~x & z);
	}

	constexpr uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) {
		return (x & y) ^ (x & z) ^ (y & z);
	}

	constexpr uint32_t Sigma0(uint32_t x) {
		return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
	}

	constexpr uint32_t Sigma1(uint32_t x) {
		return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
	}

	constexpr uint32_t sigma0(uint32_t x) {
		return ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3);
	}

	constexpr uint32_t sigma1(uint32_t x) {
		return ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10);
	}


	std::string sha256(const std::string& message)
	{
		static constexpr uint32_t K[] = {
			0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
			0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
			0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
			0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
			0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
			0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
			0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
			0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
			0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
			0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
			0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
			0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
			0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
			0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
			0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
			0x90befffa, 0xa4506ceb, 0xbef9a3a1, 0x12ba9f31
		};

		// Step 1: Pad the input message
		uint64_t messageLength = message.size() * 8;
		size_t numBlocks = ((message.size() + 8) / 64) + 1;
		size_t paddedLength = numBlocks * 64;
		unsigned char* paddedMessage = new unsigned char[paddedLength];
		std::memcpy(paddedMessage, message.c_str(), message.size());
		paddedMessage[message.size()] = 0x80;
		for (size_t i = message.size() + 1; i < paddedLength - 8; i++)
			paddedMessage[i] = 0;
		for (size_t i = 0; i < 8; i++)
			paddedMessage[paddedLength - 8 + i] = (messageLength >> (56 - i * 8)) & 0xff;

		// Step 2: Initialize hash values
		uint32_t h0 = 0x6a09e667;
		uint32_t h1 = 0xbb67ae85;
		uint32_t h2 = 0x3c6ef372;
		uint32_t h3 = 0xa54ff53a;
		uint32_t h4 = 0x510e527f;
		uint32_t h5 = 0x9b05688c;
		uint32_t h6 = 0x1f83d9ab;
		uint32_t h7 = 0x5be0cd19;

		// Step 3: Process message in 512-bit blocks
		for (size_t i = 0; i < numBlocks; i++) {
			uint32_t w[64];
			for (size_t j = 0; j < 16; j++)
				w[j] = (paddedMessage[i * 64 + j * 4] << 24) |
				(paddedMessage[i * 64 + j * 4 + 1] << 16) |
				(paddedMessage[i * 64 + j * 4 + 2] << 8) |
				(paddedMessage[i * 64 + j * 4 + 3]);
			for (size_t j = 16; j < 64; j++)
				w[j] = sigma1(w[j - 2]) + w[j - 7] + sigma0(w[j - 15]) + w[j - 16];

			uint32_t a = h0;
			uint32_t b = h1;
			uint32_t c = h2;
			uint32_t d = h3;
			uint32_t e = h4;
			uint32_t f = h5;
			uint32_t g = h6;
			uint32_t h = h7;

			for (size_t j = 0; j < 64; j++) {
				uint32_t T1 = h + Sigma1(e) + Ch(e, f, g) + K[j] + w[j];
				uint32_t T2 = Sigma0(a) + Maj(a, b, c);
				h = g;
				g = f;
				f = e;
				e = d + T1;
				d = c;
				c = b;
				b = a;
				a = T1 + T2;
			}

			h0 += a;
			h1 += b;
			h2 += c;
			h3 += d;
			h4 += e;
			h5 += f;
			h6 += g;
			h7 += h;
		}

		// Step 4: Output the hash value
		std::ostringstream oss;
		oss << std::hex << std::setfill('0') << std::setw(8) << h0
			<< std::setw(8) << h1
			<< std::setw(8) << h2
			<< std::setw(8) << h3
			<< std::setw(8) << h4
			<< std::setw(8) << h5
			<< std::setw(8) << h6
			<< std::setw(8) << h7;

		// Step 5: Clean up
		delete[] paddedMessage;

		return oss.str();
	}

	// md5:
	
	const uint32_t s[64] = 
	{
	7, 12, 17, 22,
	7, 12, 17, 22,
	7, 12, 17, 22,
	7, 12, 17, 22,
	5, 9, 14, 20,
	5, 9, 14, 20,
	5, 9, 14, 20,
	5, 9, 14, 20,
	4, 11, 16, 23,
	4, 11, 16, 23,
	4, 11, 16, 23,
	4, 11, 16, 23,
	6, 10, 15, 21,
	6, 10, 15, 21,
	6, 10, 15, 21,
	6, 10, 15, 21
	};

	const uint32_t K[64] = 
	{
		  0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
		  0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
		  0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
		  0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
		  0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
		  0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
		  0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
		  0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
		  0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
		  0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
		  0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
		  0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
		  0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
		  0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
		  0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
		  0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
	};

	std::vector<uint32_t> preprocess(const std::string& message) 
	{
		std::vector<uint32_t> message_words;
		const uint32_t block_size = 64;
		const uint32_t bits_per_byte = 8;

		uint32_t message_size = message.size();
		uint32_t padding_size = block_size - ((message_size + 8) % block_size);
		padding_size += (padding_size < 64) ? block_size : 0;

		std::vector<uint8_t> padded_message(message_size + padding_size);
		std::copy(message.begin(), message.end(), padded_message.begin());
		padded_message[message_size] = 0x80;
		uint64_t bit_length = message_size * bits_per_byte;
		std::copy(reinterpret_cast<uint8_t*>(&bit_length), reinterpret_cast<uint8_t*>(&bit_length) + sizeof(uint64_t), padded_message.end() - sizeof(uint64_t));

		for (uint32_t i = 0; i < padded_message.size(); i += 4) {
			uint32_t word = static_cast<uint32_t>(padded_message[i]) |
				(static_cast<uint32_t>(padded_message[i + 1]) << 8) |
				(static_cast<uint32_t>(padded_message[i + 2]) << 16) |
				(static_cast<uint32_t>(padded_message[i + 3]) << 24);
			message_words.push_back(word);
		}

		return message_words;
	}

	std::string md5(const std::string& message)
	{
		const uint32_t K[] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };

		auto F = [](uint32_t x, uint32_t y, uint32_t z) -> uint32_t { return (x & y) | (~x & z); };
		auto G = [](uint32_t x, uint32_t y, uint32_t z) -> uint32_t { return (x & z) | (y & ~z); };
		auto H = [](uint32_t x, uint32_t y, uint32_t z) -> uint32_t { return x ^ y ^ z; };
		auto I = [](uint32_t x, uint32_t y, uint32_t z) -> uint32_t { return y ^ (x | ~z); };

		auto leftrotate = [](uint32_t x, uint32_t c) -> uint32_t { return (x << c) | (x >> (32 - c)); };

		std::vector<uint32_t> message_words = preprocess(message);
		uint32_t a0 = K[0], b0 = K[1], c0 = K[2], d0 = K[3];

		for (size_t i = 0; i < message_words.size() - 16; i += 16) 
		{
			uint32_t A = a0, B = b0, C = c0, D = d0;

			for (size_t j = 0; j < 64; j++)
			{
				uint32_t f, g;

				if (j < 16)
				{
					f = F(B, C, D);
					g = j;
				}
				else if (j < 32) 
				{
					f = G(B, C, D);
					g = (5 * j + 1) % 16;
				}
				else if (j < 48) 
				{
					f = H(B, C, D);
					g = (3 * j + 5) % 16;
				}
				else 
				{
					f = I(B, C, D);
					g = (7 * j) % 16;
				}

				uint32_t temp = D;
				D = C;
				C = B;
				B = B + leftrotate((A + f + K[j] + message_words[i + g]), s[j]);
				A = temp;
			}

			a0 += A;
			b0 += B;
			c0 += C;
			d0 += D;
		}

		std::ostringstream result;
		result << std::hex << std::setfill('0') << std::setw(8) << a0
			<< std::hex << std::setfill('0') << std::setw(8) << b0
			<< std::hex << std::setfill('0') << std::setw(8) << c0
			<< std::hex << std::setfill('0') << std::setw(8) << d0;

		return result.str();
	}

}