// Use the DES algorithm but modify it to run with fewer rounds (e.g., 4, 8, 12) and more than the standard 16 rounds (e.g., 20, 24)
//Measure and record the encryption and decryption time for each configuration.
// write the analysis of avalanche effect by examining how much the ciphertext changes

#include <bits/stdc++.h>
using namespace std;

// Helper function for bitwise permutation
bitset<64> permute(const bitset<64>& input, const vector<int>& table) {
    bitset<64> output;
    for (size_t i = 0; i < table.size(); ++i) {
        output[63 - i] = input[63 - (table[i] - 1)];
    }
    return output;
}

// Key generation function
bitset<64> generateKey(const string& keyStr) {
    return bitset<64>(keyStr);
}

// Feistel function
inline bitset<32> feistel(const bitset<32>& halfBlock, const bitset<48>& subKey) {
    return halfBlock ^ bitset<32>(subKey.to_ulong() & 0xFFFFFFFF);
}

// Generate round keys
vector<bitset<48>> generateRoundKeys(const bitset<64>& key, int rounds) {
    vector<bitset<48>> roundKeys(rounds);
    bitset<64> mask(0xFFFFFFFFFFFF); // 48-bit mask
    for (int i = 0; i < rounds; ++i) {
        roundKeys[i] = bitset<48>((key >> (i * 4)).to_ullong() & mask.to_ullong());
    }
    return roundKeys;
}

// Encrypt function
bitset<64> desEncrypt(const bitset<64>& plaintext, const vector<bitset<48>>& roundKeys) {
    int rounds = roundKeys.size();
    bitset<32> left = (plaintext >> 32).to_ulong();
    bitset<32> right = plaintext.to_ulong() & 0xFFFFFFFF;

    for (int i = 0; i < rounds; ++i) {
        bitset<32> temp = right;
        right = left ^ feistel(right, roundKeys[i]);
        left = temp;
    }
    return (bitset<64>(left.to_ulong()) << 32) | bitset<64>(right.to_ulong());
}

// Decrypt function
bitset<64> desDecrypt(const bitset<64>& ciphertext, const vector<bitset<48>>& roundKeys) {
    int rounds = roundKeys.size();
    bitset<32> left = (ciphertext >> 32).to_ulong();
    bitset<32> right = ciphertext.to_ulong() & 0xFFFFFFFF;

    for (int i = rounds - 1; i >= 0; --i) {
        bitset<32> temp = left;
        left = right ^ feistel(left, roundKeys[i]);
        right = temp;
    }
    return (bitset<64>(left.to_ulong()) << 32) | bitset<64>(right.to_ulong());
}

// Measure execution time
template<typename Func, typename... Args>
double measureTime(Func func, Args&&... args) {
    auto start = chrono::high_resolution_clock::now();
    func(forward<Args>(args)...);
    auto end = chrono::high_resolution_clock::now();
    return chrono::duration<double, milli>(end - start).count();
}

// Count bit differences between two 64-bit bitsets
int countBitDifference(const bitset<64>& a, const bitset<64>& b) {
    return (a ^ b).count();
}

int main() {
    string key = "0001001100110100010101110111100110011011101111001101111111110001";
    string plaintext = "0000000100100011010001010110011110001001101010111100110111101111";

    bitset<64> keyBits = generateKey(key);
    bitset<64> plaintextBits(plaintext);

    vector<int> roundsConfigurations = {4, 8, 12, 16, 20, 24};
    for (int rounds : roundsConfigurations) {
        vector<bitset<48>> roundKeys = generateRoundKeys(keyBits, rounds);

        // Encryption
        double encryptTime = measureTime(desEncrypt, plaintextBits, roundKeys);
        bitset<64> ciphertext = desEncrypt(plaintextBits, roundKeys);

        // Decryption
        double decryptTime = measureTime(desDecrypt, ciphertext, roundKeys);
        bitset<64> decryptedText = desDecrypt(ciphertext, roundKeys);

        // Avalanche Effect Analysis
        bitset<64> modifiedPlaintext = plaintextBits;
        modifiedPlaintext.flip(0); // Flip a single bit
        bitset<64> modifiedCiphertext = desEncrypt(modifiedPlaintext, roundKeys);
        int avalancheEffect = countBitDifference(ciphertext, modifiedCiphertext);

        cout << "Rounds: " << rounds << "\n";
        cout << "Encryption Time: " << encryptTime << " ms\n";
        cout << "Decryption Time: " << decryptTime << " ms\n";
        cout << "Avalanche Effect (bit difference): " << avalancheEffect << "\n";
        cout << "Decryption " << (decryptedText == plaintextBits ? "Successful" : "Failed") << "\n";
        cout << "----------------------------------------\n";
    }

    return 0;
}

