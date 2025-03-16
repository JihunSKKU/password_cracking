#include "attack.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <string>

using namespace std;

/* g++ -o dictionary dictionary.cpp attack.cpp -lcrypto */
bool isValidPassphrase(const string& passphrase) {
    if (passphrase.length() != 9) 
        return false;
    for (char c : passphrase) {
        if (c < 'a' || c > 'z') 
            return false;
    }
    return true;
}

int main() {
    string ssid = "DoNotCrack_Dic";

    string packetHex = "88023a0190784139971b588694aac890588694aac89010000000aaaa03000000888e010300970213ca00100000000000000002041d27147a53a1f5e93cfb3bc34306db490c32ebb61a7c3377ef9996fa037a28041d27147a53a1f5e93cfb3bc34306dbb90f0000000000000000000000000000c1e7c0ecf17e3a7d34ba462344c740aa0038691c700c5416fbd21ca7f34131344cdbeed4361b96972f589800d12d95550844a2fedad637475b82de4c61149e2df3d7e828487ceaedf773";
    string targetMic = "c1e7c0ecf17e3a7d34ba462344c740aa";
    vector<uint8_t> eapol = changePacketToEapol(packetHex, targetMic);

    vector<uint8_t> amac = hexToBytes("588694aac890");
    vector<uint8_t> smac = hexToBytes("90784139971b");
    vector<uint8_t> anonce = hexToBytes("041d27147a53a1f5e93cfb3bc34306db490c32ebb61a7c3377ef9996fa037a28");
    vector<uint8_t> snonce = hexToBytes("c1940858a61ef3a5e0e995cddec8fb14e46df82fb8d6a2b94e4d4593d89a3ff0");
    vector<uint8_t> concMacNonce = concatMacNonce(amac, smac, anonce, snonce);

    ifstream dictFile("./files/rockyou.txt");
    if (!dictFile.is_open()) {
        cerr << "Error: could not open dictionary file" << endl;
        return 1;
    }

    string line;
    while (getline(dictFile, line)) {
        string passphrase = line;
        if (!isValidPassphrase(passphrase)) 
            continue;
        cout << "Testing: " << passphrase << endl;

        string mic = myHash(passphrase, ssid, amac, smac, snonce, anonce, concMacNonce, eapol);
        if (mic == targetMic) {
            cout << "Passphrase: " << passphrase << endl;
            dictFile.close();
            return 0;
        }
    }
    dictFile.close();
    
    cout << "Passphrase not found" << endl;
    return 1;
}