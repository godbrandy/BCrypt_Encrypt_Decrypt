#include "read_file.h"

auto constexpr STATUS_SUCCESS{ 0 };

_ReadFile::_ReadFile(const std::string& file_path, const std::string& key)
	:
	file_name{ file_path },
	key{ key }
{

}

void _ReadFile::LoadData()
{
	LoadData(file_name);
}

void _ReadFile::LoadData(const std::string& _file_name)
{
	std::ifstream file(_file_name, std::ios::binary);

	if (!file)
	{
		printf_s("Failed to open file\n");
		return;
	}

	// calculate total file size
	file.seekg(0, std::ifstream::end);
	auto file_size{ file.tellg() };
	file.seekg(0, std::ifstream::beg);

	// resize vector
	data_vec.resize(file_size);

	// read data into vector
	file.read((char*)data_vec.data(), file_size);
	file.close();
}

void _ReadFile::Encrypt()
{
	BCRYPT_ALG_HANDLE alg_handle{};
	BCRYPT_KEY_HANDLE key_handle{};

	if (BCryptOpenAlgorithmProvider(&alg_handle, BCRYPT_AES_ALGORITHM, nullptr, 0) != STATUS_SUCCESS)
	{
		printf_s("Encryption - Failed to open algorithm provider\n");
		return;
	}

	if (BCryptSetProperty(alg_handle, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB, sizeof(BCRYPT_CHAIN_MODE_ECB), 0) != STATUS_SUCCESS)
	{
		printf_s("Encryption - Failed to set property\n");
		return;
	}

	if (BCryptGenerateSymmetricKey(alg_handle, &key_handle, nullptr, 0, (PUCHAR)key.data(), (ULONG)key.size(), 0) != STATUS_SUCCESS)
	{
		printf_s("Encryption - Failed to generate symmetric key\n");
		return;
	}

	// align the file to 16 bytes
	ULONG encrypted_size{ (ULONG)data_vec.size() };

	ULONG padding{ 16 - (encrypted_size % 16) };
	encrypted_size += padding;

	std::vector<BYTE> encrypted_data(encrypted_size);

	for (size_t i{ 0 }; i < padding; i++)
	{
		data_vec.emplace_back((BYTE)padding);
	}

	if (BCryptEncrypt(key_handle, data_vec.data(), (ULONG)data_vec.size(), nullptr, nullptr, 0, encrypted_data.data(), encrypted_size, &encrypted_size, 0) != STATUS_SUCCESS)
	{
		printf_s("Encryption - Failed to perform the encryption\n");
		return;
	}

	BCryptCloseAlgorithmProvider(alg_handle, 0);
	BCryptDestroyKey(key_handle);

	size_t file_ext_pos = file_name.find_last_of('.');
	std::string output_name = file_name.substr(0, file_ext_pos) + "_enc" + file_name.substr(file_ext_pos);

	std::ofstream output(output_name, std::ios::binary);

	if (!output)
	{
		printf_s("Encryption - Failed to generate output encrypted file\n");
		return;
	}

	output.write((const char*)encrypted_data.data(), encrypted_size);
	output.close();

	printf_s("File successfully encrypted\n");
}

void _ReadFile::Decrypt()
{
	BCRYPT_ALG_HANDLE alg_handle{};
	BCRYPT_KEY_HANDLE key_handle{};

	if (BCryptOpenAlgorithmProvider(&alg_handle, BCRYPT_AES_ALGORITHM, nullptr, 0) != STATUS_SUCCESS)
	{
		printf_s("Decryption - Failed to open algorithm provider\n");
		return;
	}

	if (BCryptSetProperty(alg_handle, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB, sizeof(BCRYPT_CHAIN_MODE_ECB), 0) != STATUS_SUCCESS)
	{
		printf_s("Decryption - Failed to set property\n");
		return;
	}

	if (BCryptGenerateSymmetricKey(alg_handle, &key_handle, nullptr, 0, (PUCHAR)key.data(), (ULONG)key.size(), 0) != STATUS_SUCCESS)
	{
		printf_s("Decryption - Failed to generate symmetric key\n");
		return;
	}

	ULONG decrypted_size{ (ULONG)data_vec.size() };

	std::vector<BYTE> decrypted_data(decrypted_size);

	if (BCryptDecrypt(key_handle, data_vec.data(), (ULONG)data_vec.size(), nullptr, nullptr, 0, decrypted_data.data(), decrypted_size, &decrypted_size, 0) != STATUS_SUCCESS)
	{
		printf_s("Decryption - Failed to perform the encryption\n");
		return;
	}

	BCryptCloseAlgorithmProvider(alg_handle, 0);
	BCryptDestroyKey(key_handle);

	// deal with padding
	size_t padding = decrypted_data.back();
	decrypted_data.resize(decrypted_data.size() - padding);

	size_t file_ext_pos = file_name.find_last_of('.');
	std::string output_name = file_name.substr(0, file_ext_pos) + "_dec" + file_name.substr(file_ext_pos);

	std::ofstream output(output_name, std::ios::binary);

	if (!output)
	{
		printf_s("Decryption - Failed to generate output encrypted file\n");
		return;
	}

	output.write((const char*)decrypted_data.data(), decrypted_data.size());
	output.close();

	printf_s("File successfully decrypted\n");
}
