#pragma once

#include <string>
#include <vector>

using namespace std;

vector<uint8_t> hexToBytes(const string& hex);
string bytesToHex(const vector<uint8_t>& bytes);
vector<uint8_t> changePacketToEapol(const string& packetHex, const string& targetMic);
vector<uint8_t> concatMacNonce(const vector<uint8_t>& amac, const vector<uint8_t>& smac,
                                    const vector<uint8_t>& anonce, const vector<uint8_t>& snonce);
vector<uint8_t> makePMK(const string& passphrase, const string& ssid);
vector<uint8_t> makePTK(const vector<uint8_t>& pmk, const vector<uint8_t>& concMacNonce);
string makeMIC(const vector<uint8_t>& ptk, const vector<uint8_t>& eapol);
string myHash(const string& passphrase, const string& ssid,
              const vector<uint8_t>& amac, const vector<uint8_t>& smac,
              const vector<uint8_t>& snonce, const vector<uint8_t>& anonce,
              const vector<uint8_t>& concMacNonce, const vector<uint8_t>& eapol);
 