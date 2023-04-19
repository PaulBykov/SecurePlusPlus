#pragma once

#include <string>


namespace Secure {

	class FileOpenException;
	class FileReadException;
	class FileWriteException;
	class LocalisationException;

	// ���� ������
	void fileEncrypt(std::string fileName, std::string newFileName = "");
	void fileDecrypt(std::string fileName, std::string newFileName = "");

    // ������� �����
    std::string �aesarEncrypt(std::string text, int key, std::string localisation = "eng");
    std::string XOR(std::string text, char key);
    std::string vigenereEncrypt(std::string plaintext, std::string key);
    std::string vigenereDecrypt(std::string plaintext, std::string key);

    //sha256

	std::string sha256(const std::string& message);

    std::string md5(const std::string& message);
}