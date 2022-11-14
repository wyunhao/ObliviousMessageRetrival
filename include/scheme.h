#include "MRE.h"
#include "client.h"
#include "OMRUtil.h"
#include "MathUtil.h"


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
                    skInt[i] = uint64_t(regSk[j][tempindex].ConvertToInt() % params.q);
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

    // add encrypted extended-targetID as the last switching key based on the original logic
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

        vector<vector<int>> ids(1);
        ids[0] = targetId;
        vector<vector<int>> extended_ids = generateExponentialExtendedVector(params, ids);

        if (switchingKey.size() > params.ell) {
            for (tempn = 1; tempn < extended_ids[0].size(); tempn *= 2) {} // encrypted the exp-extended targetId for 1 x (id_size*party_size)
            vector<uint64_t> skInt(degree);
            for (size_t i = 0; i < degree; i++) {
                auto tempindex = i % uint64_t(tempn);
                if(int(tempindex) >= extended_ids[0].size()) {                                                                                                                                                                                                              
                    skInt[i] = 0;
                } else {
                    skInt[i] = uint64_t((extended_ids[0][tempindex]) % params.q);
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
    typedef mre::MREGroupPK FixedGroupSharedKey;
    typedef mre::MREsk FixedGroupSecretKey;
    typedef vector<Ciphertext> FixedGroupDetectionKey;

    vector<FixedGroupSecretKey> secretKeyGen(const PVWParam& params, const PVWsk& targetSK) {
        return mre::MREgenerateSK(params, targetSK);
    }

    FixedGroupSharedKey groupKeyGenAux(const PVWParam& params, vector<FixedGroupSecretKey>& mreSK, prng_seed_type& seed) {
        return mre::MREgeneratePartialPK(params, mreSK, seed);
    } 

    PVWCiphertext genClue(const PVWParam& param, const vector<int>& msg, const FixedGroupSharedKey& gpk, prng_seed_type& exp_seed) {
        PVWCiphertext ct;
        mre::MREEncPK(ct, msg, gpk, param, exp_seed);
        return ct;
    }

    FixedGroupDetectionKey generateDetectionKey(const SEALContext& context, const size_t& degree, const PublicKey& BFVpk, const SecretKey& BFVsk,
                                            const PVWsk& regSk, const PVWParam& params, const int partialSize = partial_size_glb, const int partySize = party_size_glb) { 
        FixedGroupDetectionKey switchingKey(params.ell);

        BatchEncoder batch_encoder(context);
        Encryptor encryptor(context, BFVpk);
        encryptor.set_secret_key(BFVsk);

        int a1_size = params.n - partialSize, a2_size = partialSize * partySize;

        int tempn = 1;
        for(tempn = 1; tempn < a1_size + a2_size; tempn *= 2){}

        vector<vector<int>> old_a2(params.ell);
        for (int i = 0; i < old_a2.size(); i++) {
            old_a2[i].resize(partialSize);

            for (int j = 0; j < partialSize; j++) {
                old_a2[i][j] = regSk[i][params.n - partialSize + j].ConvertToInt();
            }
        }
        vector<vector<int>> extended_a2 = generateExponentialExtendedVector(params, old_a2);

        for(int j = 0; j < params.ell; j++){
            vector<uint64_t> skInt(degree);
            for(size_t i = 0; i < degree; i++){
                auto tempindex = i % uint64_t(tempn);
                if (int (tempindex) >= a1_size + a2_size) {
                    skInt[i] = 0;
                } else if (int (tempindex) < a1_size) { // a1 part 
                    skInt[i] = uint64_t(regSk[j][tempindex].ConvertToInt() % params.q);
                } else { // a2 part
                    skInt[i] = extended_a2[j][tempindex - a1_size];
                }
            }

            Plaintext plaintext;
            batch_encoder.encode(skInt, plaintext);
            encryptor.encrypt_symmetric(plaintext, switchingKey[j]);
        }

        return switchingKey;
    }
}
