#pragma once

#include <string>


namespace Secure {

	class FileOpenException;
	class FileReadException;
	class FileWriteException;
	class LocalisationException;


	void fileEncrypt(std::string fileName, std::string newFileName = "");
	void fileDecrypt(std::string fileName, std::string newFileName = "");

    std::string Òaesar—rypt(std::string text, int key, std::string localisation = "eng");
    std::string XOR(std::string text, char key);

	std::string sha256(const std::string& message);

    std::string md5(const std::string& message);
}