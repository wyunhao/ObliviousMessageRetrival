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
class Sender{
    public:
        Sender();
        ~Sender();
        void GenerateClue(ClueVector& clue, Cluevectorconst CluePublicKey& pk, const PublicParams& param);
        void StreamClue(stringstream& stream /*, const ClueVector& clue*/)
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
class Receiver{
    public:
        CluePublicKey cluePK;
        DetectionKeySet detectKey;
        Receiver();
        Receiver(const PublicParams& param);
        ~Receiver();
        void GeneratePrivateKey(const PublicParams& param);
        void GenerateDetectionKeySet(const PublicParams& param /*, const PrivateKeySet& skSet*/);
        void StreamDetectionKeySet(stringstream& stream /*, const DetectionKeySet& detectKey*/);
        void DecodeDigest(vector<vector<long>> decodedMsg, const DigestedMsg& msg, const PublicParams& param /*,const PrivateKeySet& skSet*/);

    private:
        PrivateKeySet sk;
}

// For Detectors
struct DigestedMsg{
    Ciphertext DigestedIdx;
    Ciphertext DigestedPayload;
}
class Detector{
    public:
        vector<SingleDatabaseBlock> database;

        Detector();
        Detector(const PublicParams& param);
        ~Detector();
        void GenerateDigestedMsgFromDatabase(DigestedMsg& msg, const DetectionKeySet& detectKey, const PublicParams& param /*vector<SingleDatabaseBlock>& database*/);
        void StreamDigestedMsg(stringstream& stream /*, const DigestedMsg& msg*/);
}

// How it works:
// 1. Sender generate normal payload, and generate a clue with GenerateClue(...), and pack them.
// 2. The new block is appended to the blockchain.
// 3. Receiver generates private keys with GeneratePrivateKey(...) and generate detection keys with StreamDetectionKeySet(...) using private keys.
// 4. Receiver sends the detection keys to the detector
// 5. Detector digest the whole database and generated digested msg with GenerateDigestedMsgFromDatabase(...)
// 6. Detector returns the digestedMsg
