#include <HalonMTA.h>
#include <string>
#include <cstring>
#include <openssl/evp.h>
#include <syslog.h>

enum des_type
{
	DES_CBC,
	DES_ECB,
	DES_CFB,
	DES_OFB,
	DES_EDE3_CBC,
	DES_EDE3,
	DES_EDE3_CFB,
	DES_EDE3_OFB,
};

bool des_encrypt(const std::string& data, const std::string& deskey,
	const std::string& iv, std::string& result, des_type type, bool pad);
bool des_decrypt(const std::string& data, const std::string& deskey,
	const std::string& iv, std::string& result, des_type type, bool pad);
void des(HalonHSLContext* hhc, HalonHSLArguments* args, HalonHSLValue* ret, bool encrypt);

HALON_EXPORT
int Halon_version()
{
	return HALONMTA_PLUGIN_VERSION;
}

void des(HalonHSLContext* hhc, HalonHSLArguments* args, HalonHSLValue* ret, bool encrypt)
{
	HalonHSLValue* x = HalonMTA_hsl_argument_get(args, 0);
	char* message = nullptr;
	size_t messagelen;
	if (!x || HalonMTA_hsl_value_type(x) != HALONMTA_HSL_TYPE_STRING ||
			!HalonMTA_hsl_value_get(x, HALONMTA_HSL_TYPE_STRING, &message, &messagelen))
	{
		return;
	}

	x = HalonMTA_hsl_argument_get(args, 1);
	char* key = nullptr;
	size_t keylen;
	if (!x || HalonMTA_hsl_value_type(x) != HALONMTA_HSL_TYPE_STRING ||
			!HalonMTA_hsl_value_get(x, HALONMTA_HSL_TYPE_STRING, &key, &keylen))
	{
		return;
	}

	x = HalonMTA_hsl_argument_get(args, 2);
	const char* mode_ = "des-cbc";
	size_t modelen_ = strlen(mode_);
	if (x && (HalonMTA_hsl_value_type(x) != HALONMTA_HSL_TYPE_STRING ||
			!HalonMTA_hsl_value_get(x, HALONMTA_HSL_TYPE_STRING, &mode_, &modelen_)))
	{
		return;
	}

	std::string mode(mode_, modelen_);
	des_type destype;
	if (mode == "cbc") destype = DES_CBC;
	else if (mode == "ecb") destype = DES_ECB;
	else if (mode == "cfb") destype = DES_CFB;
	else if (mode == "ofb") destype = DES_OFB;
	else if (mode == "ede3-cbc") destype = DES_EDE3_CBC;
	else if (mode == "ede3") destype = DES_EDE3;
	else if (mode == "ede3-cfb") destype = DES_EDE3_CFB;
	else if (mode == "ede3-ofb") destype = DES_EDE3_OFB;
	else
	{
		syslog(LOG_ERR, "unknown mode");
		return;
	}

	const char* iv = "";
	size_t ivlen = 0;
	bool padding = true;

	x = HalonMTA_hsl_argument_get(args, 3);
	if (x)
	{
		if (HalonMTA_hsl_value_type(x) != HALONMTA_HSL_TYPE_ARRAY)
			return;

		size_t index = 0;
		HalonHSLValue *key, *val;
		while ((val = HalonMTA_hsl_value_array_get(x, index++, &key)))
		{
			const char* optkey_;
			size_t optkeylen_;
			if (HalonMTA_hsl_value_type(key) != HALONMTA_HSL_TYPE_STRING ||
				!HalonMTA_hsl_value_get(key, HALONMTA_HSL_TYPE_STRING, &optkey_, &optkeylen_))
				continue;
			
			std::string optkey(optkey_, optkeylen_);
			if (optkey == "iv")
			{
				if (HalonMTA_hsl_value_type(val) == HALONMTA_HSL_TYPE_STRING)
					HalonMTA_hsl_value_get(val, HALONMTA_HSL_TYPE_STRING, &iv, &ivlen);
				continue;
			}
			if (optkey == "padding")
			{
				if (HalonMTA_hsl_value_type(val) == HALONMTA_HSL_TYPE_BOOLEAN)
					HalonMTA_hsl_value_get(val, HALONMTA_HSL_TYPE_BOOLEAN, &padding, nullptr);
				continue;
			}
		}
	}

	std::string result;
	if (encrypt)
	{
		if (!des_encrypt(std::string(message, messagelen), std::string(key, keylen), std::string(iv, ivlen), result, destype, padding))
			return;
	}
	else
	{
		if (!des_decrypt(std::string(message, messagelen), std::string(key, keylen), std::string(iv, ivlen), result, destype, padding))
		return;	
	}
	HalonMTA_hsl_value_set(ret, HALONMTA_HSL_TYPE_STRING, result.c_str(), result.size());
}

HALON_EXPORT
void des_encrypt(HalonHSLContext* hhc, HalonHSLArguments* args, HalonHSLValue* ret)
{
	des(hhc, args, ret, true);
}

HALON_EXPORT
void des_decrypt(HalonHSLContext* hhc, HalonHSLArguments* args, HalonHSLValue* ret)
{
	des(hhc, args, ret, false);
}

HALON_EXPORT
bool Halon_hsl_register(HalonHSLRegisterContext* ptr)
{
	HalonMTA_hsl_module_register_function(ptr, "des_encrypt", &des_encrypt);
	HalonMTA_hsl_module_register_function(ptr, "des_decrypt", &des_decrypt);
	HalonMTA_hsl_register_function(ptr, "des_encrypt", &des_encrypt);
	HalonMTA_hsl_register_function(ptr, "des_decrypt", &des_decrypt);
	return true;
}

bool des_encrypt(const std::string& data, const std::string& deskey, const std::string& iv, std::string& result, des_type type, bool pad)
{
	unsigned char* enctext = nullptr;
	int encryptlen, enclen = 0;
	bool success = false;

	const EVP_CIPHER* _type = EVP_des_cbc();
	switch (type)
	{
		case DES_CBC:		_type = EVP_des_cbc(); break;
		case DES_ECB:		_type = EVP_des_ecb(); break;
		case DES_CFB:		_type = EVP_des_cfb(); break;
		case DES_OFB:		_type = EVP_des_ofb(); break;
		case DES_EDE3_CBC:	_type = EVP_des_ede3_cbc(); break;
		case DES_EDE3:		_type = EVP_des_ede3(); break;
		case DES_EDE3_CFB:	_type = EVP_des_ede3_cfb(); break;
		case DES_EDE3_OFB:	_type = EVP_des_ede3_ofb(); break;
	}

	if (EVP_CIPHER_key_length(_type) != deskey.size())
	{
		syslog(LOG_ERR, "key length mismatch %d / %ld", EVP_CIPHER_key_length(_type), deskey.size());
		return false;
	}

	if (EVP_CIPHER_iv_length(_type) != iv.size())
	{
		syslog(LOG_ERR, "iv mismatch %d / %ld", EVP_CIPHER_iv_length(_type), iv.size());
		return false;
	}

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!EVP_EncryptInit_ex(ctx, _type, nullptr, (unsigned char*)deskey.c_str(), (unsigned char*)iv.c_str()))
		goto cleanup;
	if (!pad) EVP_CIPHER_CTX_set_padding(ctx, 0);

	enctext = (unsigned char*)malloc(data.size() + EVP_CIPHER_CTX_block_size(ctx));
	if (!EVP_EncryptUpdate(ctx, enctext, &encryptlen,
				(unsigned char*)data.c_str(), (int)data.size()))
		goto cleanup;
	enclen += encryptlen;
	if (!EVP_EncryptFinal_ex(ctx, enctext + enclen, &encryptlen))
		goto cleanup;
	enclen += encryptlen;

	result = std::string((char*)enctext, enclen);
	success = true;

cleanup:
	EVP_CIPHER_CTX_free(ctx);
	free(enctext);
	return success;
}

bool des_decrypt(const std::string& data, const std::string& deskey, const std::string& iv, std::string& result, des_type type, bool pad)
{
	unsigned char* plaintext = nullptr;
	int decryptlen, plainlen = 0;
	bool success = false;

	const EVP_CIPHER* _type = EVP_des_cbc();
	switch (type)
	{
		case DES_CBC:		_type = EVP_des_cbc(); break;
		case DES_ECB:		_type = EVP_des_ecb(); break;
		case DES_CFB:		_type = EVP_des_cfb(); break;
		case DES_OFB:		_type = EVP_des_ofb(); break;
		case DES_EDE3_CBC:	_type = EVP_des_ede3_cbc(); break;
		case DES_EDE3:		_type = EVP_des_ede3(); break;
		case DES_EDE3_CFB:	_type = EVP_des_ede3_cfb(); break;
		case DES_EDE3_OFB:	_type = EVP_des_ede3_ofb(); break;
	}

	if (EVP_CIPHER_key_length(_type) != deskey.size())
	{
		syslog(LOG_ERR, "key length mismatch %d / %ld", EVP_CIPHER_key_length(_type), deskey.size());
		return false;
	}

	if (EVP_CIPHER_iv_length(_type) != iv.size())
	{
		syslog(LOG_ERR, "iv mismatch %d / %ld", EVP_CIPHER_iv_length(_type), iv.size());
		return false;
	}

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!EVP_DecryptInit_ex(ctx, _type, nullptr, (unsigned char*)deskey.c_str(), (unsigned char*)iv.c_str()))
		goto cleanup;
	if (!pad) EVP_CIPHER_CTX_set_padding(ctx, 0);

	plaintext = (unsigned char*)malloc(data.size());
	if (!EVP_DecryptUpdate(ctx, plaintext, &decryptlen,
				(unsigned char*)data.c_str(), (int)data.size()))
		goto cleanup;
	plainlen += decryptlen;

	if (!EVP_DecryptFinal_ex(ctx, plaintext + plainlen, &decryptlen))
		goto cleanup;
	plainlen += decryptlen;

	result = std::string((char*)plaintext, plainlen);
	success = true;

cleanup:
	EVP_CIPHER_CTX_free(ctx);
	free(plaintext);
	return success;
}