#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <fstream>

using namespace std;

// Function to generate an RSA key pair
void generateKeyPair() {
    RSA* rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    
    FILE* privFile = fopen("private.pem", "wb");
    PEM_write_RSAPrivateKey(privFile, rsa, NULL, NULL, 0, NULL, NULL);
    fclose(privFile);
    
    FILE* pubFile = fopen("public.pem", "wb");
    PEM_write_RSA_PUBKEY(pubFile, rsa);
    fclose(pubFile);
    
    RSA_free(rsa);
    cout << "Key pair generated successfully." << endl;
}

// Function to sign a document
void signDocument(const string& filename) {
    ifstream file(filename, ios::binary);
    if (!file) {
        cerr << "File not found!" << endl;
        return;
    }
    
    string content((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
    file.close();
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)content.c_str(), content.length(), hash);
    
    FILE* privFile = fopen("private.pem", "rb");
    RSA* rsa = PEM_read_RSAPrivateKey(privFile, NULL, NULL, NULL);
    fclose(privFile);
    
    unsigned char signature[256];
    unsigned int sigLen;
    RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature, &sigLen, rsa);
    
    ofstream sigFile("signature.sig", ios::binary);
    sigFile.write((char*)signature, sigLen);
    sigFile.close();
    
    RSA_free(rsa);
    cout << "Document signed successfully." << endl;
}

// Function to verify a document
bool verifyDocument(const string& filename) {
    ifstream file(filename, ios::binary);
    if (!file) {
        cerr << "File not found!" << endl;
        return false;
    }
    
    string content((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
    file.close();
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)content.c_str(), content.length(), hash);
    
    FILE* pubFile = fopen("public.pem", "rb");
    RSA* rsa = PEM_read_RSA_PUBKEY(pubFile, NULL, NULL, NULL);
    fclose(pubFile);
    
    ifstream sigFile("signature.sig", ios::binary);
    if (!sigFile) {
        cerr << "Signature file not found!" << endl;
        return false;
    }
    
    unsigned char signature[256];
    sigFile.read((char*)signature, 256);
    sigFile.close();
    
    int result = RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature, 256, rsa);
    RSA_free(rsa);
    
    if (result == 1) {
        cout << "Signature verified successfully." << endl;
        return true;
    } else {
        cout << "Signature verification failed!" << endl;
        return false;
    }
}

int main() {
    int choice;
    string filename;
    
    cout << "1. Generate Key Pair" << endl;
    cout << "2. Sign Document" << endl;
    cout << "3. Verify Document" << endl;
    cout << "Enter your choice: ";
    cin >> choice;
    
    switch (choice) {
        case 1:
            generateKeyPair();
            break;
        case 2:
            cout << "Enter filename to sign: ";
            cin >> filename;
            signDocument(filename);
            break;
        case 3:
            cout << "Enter filename to verify: ";
            cin >> filename;
            verifyDocument(filename);
            break;
        default:
            cout << "Invalid choice!" << endl;
    }
    return 0;
}