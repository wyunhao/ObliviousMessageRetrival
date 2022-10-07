#include "MRE.h"
#include "client.h"
#include "OMRUtil.h"


////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////// Assistant Function /////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////

// Read in the a/b[i] part as a 1 x partySize RHS vector for Oblivious Multiplexer polynomial.
void prepareClueRhs(vector<vector<int>>& rhs, const vector<PVWCiphertext> clues, int index, bool prepare) {
    for (int i = 0; i < rhs.size(); i++) {
        if (index >= clues[i].a.GetLength()) {
            if (prepare) {
                int temp = clues[i].b[index - clues[i].a.GetLength()].ConvertToInt() - 16384;
                rhs[i][0] = temp < 0 ? temp + 65537 : temp % 65537;
            } else {
                rhs[i][0] = clues[i].b[index - clues[i].a.GetLength()].ConvertToInt();
            }
        } else {
            rhs[i][0] = clues[i].a[index].ConvertToInt();
        }
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////// OMR schemes ////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * @brief Oblivious Message Retrival
 */
namespace omr
{
    vector<Ciphertext> generateDetectionKey(const SEALContext& context, const size_t& degree,
                                            const PublicKey& BFVpk, const SecretKey& BFVsk,
                                            const PVWsk& regSk, const PVWParam& params) { 
        vector<Ciphertext> switchingKey(params.ell);

        BatchEncoder batch_encoder(context);
        Encryptor encryptor(context, BFVpk);
        encryptor.set_secret_key(BFVsk);

        int tempn = 1;
        for(tempn = 1; tempn < params.n; tempn *= 2){}
        for(int j = 0; j < params.ell; j++){
            vector<uint64_t> skInt(degree);
            for(size_t i = 0; i < degree; i++){
                auto tempindex = i%uint64_t(tempn);
                if(int(tempindex) >= params.n) {
                    skInt[i] = 0;
                } else {
                    skInt[i] = uint64_t(regSk[j][tempindex].ConvertToInt() % 65537);
                }
            }
            Plaintext plaintext;
            batch_encoder.encode(skInt, plaintext);
            encryptor.encrypt_symmetric(plaintext, switchingKey[j]);
        }

        return switchingKey;
    }
}


/**
 * @brief Ad-hoc Group Oblivious Message Retrival
 */
namespace agomr
{
    typedef vector<vector<long>> AdhocGroupClue;
    typedef vector<Ciphertext> AdhocDetectionKey;

    // add encrypted targetID as the last switching key based on the original logic
    AdhocDetectionKey generateDetectionKey(const vector<int>& targetId, const SEALContext& context, const size_t& degree, 
                            const PublicKey& BFVpk, const SecretKey& BFVsk, const PVWsk& regSk, const PVWParam& params) {
        
        AdhocDetectionKey switchingKey(params.ell + 1);

        BatchEncoder batch_encoder(context);
        Encryptor encryptor(context, BFVpk);
        encryptor.set_secret_key(BFVsk);

        int tempn = 1;
        for (; tempn < params.n; tempn *= 2) {}
        for (int j = 0; j < params.ell; j++) {
            vector<uint64_t> skInt(degree);
            for (size_t i = 0; i < degree; i++){
                auto tempindex = i%uint64_t(tempn);
                if(int(tempindex) >= params.n) {
                    skInt[i] = 0;
                } else {
                    skInt[i] = uint64_t(regSk[j][tempindex].ConvertToInt() % params.q);
                }
            }
            Plaintext plaintext;
            batch_encoder.encode(skInt, plaintext);
            encryptor.encrypt_symmetric(plaintext, switchingKey[j]);
        }

        if (switchingKey.size() > params.ell) {
            for (tempn = 1; tempn < targetId.size(); tempn *= 2) {} // encrypted the targetId for 1 * id_size
            vector<uint64_t> skInt(degree);
            for (size_t i = 0; i < degree; i++) {
                auto tempindex = i % uint64_t(tempn);
                if(int(tempindex) >= targetId.size()) {
                    skInt[i] = 0;
                } else {
                    skInt[i] = uint64_t((targetId[tempindex]) % params.q);
                }
            }
            Plaintext plaintext;
            batch_encoder.encode(skInt, plaintext);
            encryptor.encrypt_symmetric(plaintext, switchingKey[switchingKey.size() - 1]);
        }

        return switchingKey;
    }


    AdhocGroupClue generateClue(const PVWParam& params, vector<PVWCiphertext> clues, vector<vector<int>> ids, bool prepare = false, int clueLength = 454) {
        vector<vector<long>> temp;
        AdhocGroupClue cluePolynomial(clueLength, vector<long>(party_size_glb));
        for (int a = 0; a < clueLength; a++) {
            vector<vector<int>> rhs(ids.size(), vector<int>(1, -1));
            vector<vector<int>> lhs = ids;
            prepareClueRhs(rhs, clues, a, prepare);

            temp = equationSolvingRandom(lhs, rhs, -1);

            for(int j = 0; j < party_size_glb; j++){
                cluePolynomial[a][j] = temp[j][0];
            }
        }

        return cluePolynomial;
    }
}


/**
 * @brief Fixed Group Oblivious Message Retrival
 */
namespace fgomr
{
    typedef mre::MREPublicKey FixedGroupPublicKey;
    typedef vector<mre::MREpk> FixedGroupSharedKey;
    typedef mre::MREsk FixedGroupSecretKey;
    typedef vector<Ciphertext> FixedGroupDetectionKey;
    // typedef PVWCiphertext FGClue;

    vector<FixedGroupSecretKey> secretKeyGen(const PVWParam& params) {
        return mre::MREgenerateSK(params);
    }

    // take MRE sk's and output switching key, which is a ciphertext of size \ell*n, where n is the PVW secret key dimension (enlarged under MRE requirement)
    FixedGroupDetectionKey generateDetectionKey(const PVWParam& params, const SEALContext& context, const size_t& degree, 
                                                const PublicKey& pk, const SecretKey& sk, const FixedGroupSecretKey& regSk) {
        
        BatchEncoder batch_encoder(context);
        Encryptor encryptor(context, pk);
        FixedGroupDetectionKey switchingKey(params.ell);

        // Use symmetric encryption to enable seed mode to reduce the detection key size
        encryptor.set_secret_key(sk);

        int tempn = 1;
        for (tempn = 1; tempn < params.n; tempn *= 2) {}
        for (int j = 0; j < params.ell; j++) {
            // encrypt into ell BFV ciphertexts
            vector<uint64_t> skInt(degree);
            for (size_t i = 0; i < degree; i++) {
                auto tempindex = i % uint64_t(tempn);
                if (int(tempindex) >= params.n) {
                    skInt[i] = 0;
                } else {
                    if (tempindex < params.n - partial_size_glb) {
                        skInt[i] = uint64_t(regSk.secretSK[j][tempindex].ConvertToInt() % params.q);
                    } else {
                        skInt[i] = uint64_t(regSk.shareSK[j][tempindex - params.n + partial_size_glb].ConvertToInt() % params.q);
                    }
                }
            }
            Plaintext plaintext;
            batch_encoder.encode(skInt, plaintext);
            encryptor.encrypt_symmetric(plaintext, switchingKey[j]);
        }

        return switchingKey;
    }

    FixedGroupSharedKey groupKeyGenAux(const PVWParam& params, vector<FixedGroupSecretKey>& mreSK, prng_seed_type& seed) {
        return mre::MREgeneratePartialPK(params, mreSK, seed);
    } 

    FixedGroupPublicKey keyGen(const PVWParam& params, FixedGroupSharedKey& mrePK, prng_seed_type& seed, const int partySize = 8, const int partialSize = 40) {
        return mre::MREgeneratePK(params, mrePK, seed, partySize, partialSize);
    }

    PVWCiphertext genClue(const PVWParam& param, const vector<int>& msg, const FixedGroupPublicKey& pk) {
        chrono::high_resolution_clock::time_point time_start, time_end;
        chrono::microseconds time_diff;
        time_start = chrono::high_resolution_clock::now();
        PVWCiphertext ct;
        prng_seed_type seed;
        for (auto &i : seed) {
            i = random_uint64();
        }

        auto rng = make_shared<Blake2xbPRNGFactory>(Blake2xbPRNGFactory(seed));
        RandomToStandardAdapter engine(rng->create());
        uniform_int_distribution<uint64_t> dist(0, 1);

        NativeInteger q = param.q;
        ct.a = NativeVector(param.n);
        ct.b = NativeVector(param.ell);
        for(size_t i = 0; i < pk.groupPK.size(); i++){
            if (!verifyPK(param, pk.groupPK[i], pk.recipientPK[i].b_prime, pk.recipientPK[i].shareSK)) {
                continue;
            }
            if (dist(engine)){
                for(int j = 0; j < param.n; j++){
                    ct.a[j].ModAddFastEq(pk.groupPK[i].A[j], q);
                }
                for(int j = 0; j < param.ell; j++){
                    ct.b[j].ModAddFastEq(pk.groupPK[i].b[j], q);
                }
            }
        }
        for(int j = 0; j < param.ell; j++){
            msg[j]? ct.b[j].ModAddFastEq(3*q/4, q) : ct.b[j].ModAddFastEq(q/4, q);
        }

        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        cout << "\nClue generation for one message: " << time_diff.count() << "us." << "\n";
        return ct;
    }
}
