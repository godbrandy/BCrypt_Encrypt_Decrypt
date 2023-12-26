#pragma once
#pragma comment(lib, "bcrypt.lib")
#include <Windows.h>
#include <string>
#include <vector>
#include <fstream>
#include <bcrypt.h>

class _ReadFile
{
public:
	_ReadFile(const std::string& file_path, const std::string& key);
	void LoadData();
	void LoadData(const std::string& file_name);
	void Encrypt();
	void Decrypt();
private:
	const std::string file_name;
	const std::string key;
	std::vector<BYTE> data_vec;
};