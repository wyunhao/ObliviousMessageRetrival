//#include "regevToBFV.h"
#include "unitTests.h"
#include "LoadAndSaveUtils.h"

// Public
struct PublicParams{
    PVWParam ClueParam;
    SEALContext DetectionParam;
    size_t degree;
    size_t payloadSize;
    int num_of_transactions;
}

// For Senders
struct SingleDatabaseBlock{
    PVWCiphertext clue;
    vector<uint64_t> payload;
}

// For Receivers
typedef vector<PVWCiphertext> ClueKey;
struct DetectionKeySet{
    vector<Ciphertext> SwtichingKey;
    GaloisKeys RotKey;
    RelinKeys Rlk;
}
struct PrivateKeySet{
    PVWsk ClueSK;
    SecretKey BfvSk;
}

// For Detectors
struct TheDigest{
    vector<Ciphertext> DigestedIdx;
    vector<Ciphertext> DigestedPayload;
}

// Sender class
class Sender{
    public:
        Sender();
        ~Sender();
        void GenerateClue(PVWCiphertext& clue, Cluevectorconst ClueKey& pk, const PublicParams& param);
        void StreamClue(stringstream& stream, const PVWCiphertext& clue)
}

// Receiver class
class Receiver{
    public:
        CluePublicKey cluePK;
        DetectionKeySet detectKey;

        Receiver();
        Receiver(const PublicParams& param);
        ~Receiver();
        void GeneratePrivateKey(const PublicParams& param);
        void GenerateDetectionKeySet(const PublicParams& param);
        void StreamDetectionKeySet(stringstream& stream);
        void DecodeDigest(vector<vector<long>> decodedMsg, const TheDigest& msg, const PublicParams& param);

    private:
        PrivateKeySet sk;
}

// Detector class
class Detector{
    public:
        vector<SingleDatabaseBlock> database;

        Detector();
        Detector(const PublicParams& param);
        ~Detector();
        void GenerateDigestedMsgFromDatabase(DigestedMsg& msg, const DetectionKeySet& detectKey, const PublicParams& param);
        void StreamDigestedMsg(stringstream& stream, const DigestedMsg& msg);
}

// How it works:
// 1. Sender generate normal payload, and generate a clue with GenerateClue(...), and pack them.
// 2. The new block is appended to the blockchain.
// 3. Receiver generates private keys with GeneratePrivateKey(...) and generate detection keys with StreamDetectionKeySet(...) using private keys.
// 4. Receiver sends the detection keys to the detector
// 5. Detector digest the whole database and generated digested msg with GenerateTheDigestFromDatabase(...)
// 6. Detector returns the TheDigest