//#include "regevToBFV.h"
#include "unitTests.h"
#include "LoadAndSaveUtils.h"

// Public
struct PublicParams{
    regevParam ClueParam;
    SEALContext DetectionParam;
    size_t degree;
    size_t payloadSize;
    int num_of_transactions;
}

// For Senders
typedef vector<regevCiphertext> ClueVector;
struct SingleDatabaseBlock{
    ClueVector clue;
    vector<uint64_t> payload;
}

// For Receivers
typedef vector<regevCiphertext> CluePublicKey;
struct DetectionKeySet{
    vector<Ciphertext> SwtichingKey;
    GaloisKeys RotKey;
    RelinKeys Rlk;
    int seed;
}
struct PrivateKeySet{
    regevSK ClueSK;
    SecretKey BfvSk;
}

// For Detectors
struct DigestedMsg{
    Ciphertext DigestedIdx;
    Ciphertext DigestedPayload;
}

// Sender-side function
void GenerateClue(ClueVector& clue, const CluePublicKey& pk, const PublicParams& param);
void StreamClue(stringstream& stream, const ClueVector& clue)

// Receiver-side function
void GeneratePrivateKey(PrivateKeySet& skSet,  const PublicParams& param);
void GenerateDetectionKeySet(DetectionKeySet& detectKey, const PrivateKeySet& skSet, const PublicParams& param);
void StreamDetectionKeySet(stringstream& stream, const DetectionKeySet& detectKey);
void DecodeDigest(vector<vector<long>> decodedMsg, const DigestedMsg& msg, const PrivateKeySet& skSet,  const PublicParams& param);

// Detector-side function
void GenerateDigestedMsgFromDatabase(DigestedMsg& msg, const DetectionKeySet& detectKey, vector<SingleDatabaseBlock>& database, , const PublicParams& param);
void StreamDigestedMsg(stringstream& stream, const DigestedMsg& msg);

// How it works:
// 1. Sender generate normal payload, and generate a clue with GenerateClue(...), and pack them.
// 2. The new block is appended to the blockchain.
// 3. Receiver generates private keys with GeneratePrivateKey(...) and generate detection keys with StreamDetectionKeySet(...) using private keys.
// 4. Receiver sends the detection keys to the detector
// 5. Detector digest the whole database and generated digested msg with GenerateDigestedMsgFromDatabase(...)
// 6. Detector returns the digestedMsg