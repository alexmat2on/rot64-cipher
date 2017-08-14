#include <iostream>
#include <bitset>
#include <string>
#include <algorithm>
using namespace std;

/*
   base64.cpp and base64.h
   base64 encoding and decoding with C++.
   Version: 1.01.00
   Copyright (C) 2004-2017 René Nyffenegger
   This source code is provided 'as-is', without any express or implied
   warranty. In no event will the author be held liable for any damages
   arising from the use of this software.
   Permission is granted to anyone to use this software for any purpose,
   including commercial applications, and to alter it and redistribute it
   freely, subject to the following restrictions:
   1. The origin of this source code must not be misrepresented; you must not
      claim that you wrote the original source code. If you use this source code
      in a product, an acknowledgment in the product documentation would be
      appreciated but is not required.
   2. Altered source versions must be plainly marked as such, and must not be
      misrepresented as being the original source code.
   3. This notice may not be removed or altered from any source distribution.
   René Nyffenegger rene.nyffenegger@adp-gmbh.ch
*/

#include "base64.h"
#include <iostream>

static const std::string base64_chars =
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789+/";


static inline bool is_base64(unsigned char c) {
  return (isalnum(c) || (c == '+') || (c == '/'));
}

std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len) {
  std::string ret;
  int i = 0;
  int j = 0;
  unsigned char char_array_3[3];
  unsigned char char_array_4[4];

  while (in_len--) {
    char_array_3[i++] = *(bytes_to_encode++);
    if (i == 3) {
      char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
      char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
      char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
      char_array_4[3] = char_array_3[2] & 0x3f;

      for(i = 0; (i <4) ; i++)
        ret += base64_chars[char_array_4[i]];
      i = 0;
    }
  }

  if (i)
  {
    for(j = i; j < 3; j++)
      char_array_3[j] = '\0';

    char_array_4[0] = ( char_array_3[0] & 0xfc) >> 2;
    char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
    char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

    for (j = 0; (j < i + 1); j++)
      ret += base64_chars[char_array_4[j]];

    while((i++ < 3))
      ret += '=';

  }

  return ret;

}

std::string base64_decode(std::string const& encoded_string) {
  int in_len = encoded_string.size();
  int i = 0;
  int j = 0;
  int in_ = 0;
  unsigned char char_array_4[4], char_array_3[3];
  std::string ret;

  while (in_len-- && ( encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
    char_array_4[i++] = encoded_string[in_]; in_++;
    if (i ==4) {
      for (i = 0; i <4; i++)
        char_array_4[i] = base64_chars.find(char_array_4[i]);

      char_array_3[0] = ( char_array_4[0] << 2       ) + ((char_array_4[1] & 0x30) >> 4);
      char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
      char_array_3[2] = ((char_array_4[2] & 0x3) << 6) +   char_array_4[3];

      for (i = 0; (i < 3); i++)
        ret += char_array_3[i];
      i = 0;
    }
  }

  if (i) {
    for (j = 0; j < i; j++)
      char_array_4[j] = base64_chars.find(char_array_4[j]);

    char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
    char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);

    for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
  }

  return ret;
}

// -----------------------------------------------------------------------------
static string rotN(int n, string str) {
    // if n < 0, it reverses a rotation
    string output = str;
    int stringLen = str.size();
    for (int i = 0; i < stringLen; i++) {
        if (output[i] + n > 126) {
            // If the value is too high, wrap around to ASCII 32 (" ")
            output[i] = output[i] + n - 94;
        } else if (output[i] + n < 32) {
            // If the value is too low (for reverse rotations), wrap around to ASCII 126 ("~")
            output[i] = 127 - (32 - output[i] + n);
        } else {
            output[i] = output[i] + n;
        }
    }

    return output;
}

static string rot64Encrypt(int rotations, string msg) {
    string ciphertext = msg;
    for (int i = 0; i < rotations; i++) {
        string r = rotN(1, ciphertext);
        ciphertext = base64_encode(reinterpret_cast<const unsigned char*>(r.c_str()), r.length());
    }
    return ciphertext;
}

static string rot64Encrypt(int rotations, string key, string msg) {
	string ciphertext = msg;
	int keyLen = key.size();
	int msgLen = msg.size();
	
	if (keyLen < msgLen) {
		for(int i=keyLen-1; i < msgLen; i++) {
			int x = 0;
			key += key[x];
			x++;
		}
	}

	for (int i=0; i < msgLen; i++) {
		string r = rotN(key[i], ciphertext);
		ciphertext = base64_encode(reinterpret_cast<const unsigned char*>(r.c_str()), r.length());
    }
	return ciphertext;
}

static string rot64Decrypt(int rotations, string cipher) {
    string plaintext = cipher;
    for (int i = 0; i < rotations; i++) {
        plaintext = base64_decode(plaintext);
        plaintext = rotN(-1, plaintext);
    }
    return plaintext;
}

static string rot64Decrypt(int rotations, string key, string cipher) {
	string plaintext = cipher;
	int keyLen = key.size();                                int msgLen = cipher.size();
                                                                if (keyLen < msgLen) {
                for(int i=keyLen-1; i < msgLen; i++) {
                        int x = 0;
                        key += key[x];
                        x++;
                }                                               }
								int x = key.size() - 1;
								for (int i = 0; i < rotations; i++) {				int y = key[x] * -1;
		plaintext = base64_decode(plaintext);                   plaintext = rotN(y, plaintext);
		x--;
    }                                                       return plaintext;
}

int main() {
    // EXAMPLE RUN:
    int rotations = 5;

    string message = "Hi friend";
    string ciphertext = rot64Encrypt(rotations, message);
    string key = "key";
    string keyedcipher = rot64Encrypt(rotations, key, message);

    cout << "Initial message:" << message << endl
         << "Encrypted: " << ciphertext << endl
         << "Decrypted: " << rot64Decrypt(rotations, ciphertext) << endl << endl;

    cout << "Key encrypted: " << keyedcipher << endl
	    << "Key decrypted: " << rot64Decrypt(rotations, key, ciphertext) << endl;

    return 0;
}
