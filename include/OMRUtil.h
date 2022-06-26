#pragma once

#include "PVWToBFVSeal.h"
#include "SealUtils.h"
#include "retrieval.h"
#include "client.h"
#include "LoadAndSaveUtils.h"
#include "OMRUtil.h"
#include "global.h"
#include <NTL/BasicThreadPool.h>
#include <NTL/ZZ.h>
#include <thread>

using namespace seal;


vector<vector<uint64_t>> preparingTransactionsFormal(vector<int>& pertinentMsgIndices, PVWpk& pk, int numOfTransactions, int pertinentMsgNum,
                                                      const PVWParam& params, int partySize = 1) {
    srand (time(NULL));

    vector<int> msgs(numOfTransactions);
    vector<vector<uint64_t>> ret;
    vector<int> zeros(params.ell, 0);

    for(int i = 0; i < pertinentMsgNum;){
        auto temp = rand() % numOfTransactions;
        while(msgs[temp]){
            temp = rand() % numOfTransactions;
        }
        msgs[temp] = 1;
        pertinentMsgIndices.push_back(temp);
        i++;
    }

    cout << "Expected Message Indices: ";

    for(int i = 0; i < numOfTransactions; i++){
        PVWCiphertext tempclue;

        // create clues with new SK for the rest of messages in the same group
        for (int p = 0; p < partySize - 1; p++) {
            PVWCiphertext tempclue;
            auto sk2 = PVWGenerateSecretKey(params);
            PVWEncSK(tempclue, zeros, sk2, params);
            saveClues(tempclue, i*partySize + p);
        }

        // w.l.o.g assume the index of recipient within party is |partySize - 1|, i.e., the last in the group
        if(msgs[i]){
            cout << i << " ";
            PVWEncPK(tempclue, zeros, pk, params);
            ret.push_back(loadDataSingle(i));
            expectedIndices.push_back(uint64_t(i));
        }
        else
        {
            auto sk2 = PVWGenerateSecretKey(params);
            PVWEncSK(tempclue, zeros, sk2, params);
        }
        saveClues(tempclue, i*partySize + partySize - 1);
    }
    cout << endl;
    return ret;
}

// Phase 1, obtaining PV's
Ciphertext serverOperations1obtainPackedSIC(vector<PVWCiphertext>& SICPVW, vector<Ciphertext> switchingKey, const RelinKeys& relin_keys,
                            const GaloisKeys& gal_keys, const size_t& degree, const SEALContext& context, const PVWParam& params, const int numOfTransactions){
    Evaluator evaluator(context);
    
    vector<Ciphertext> packedSIC(params.ell);
    computeBplusASPVWOptimized(packedSIC, SICPVW, switchingKey, gal_keys, context, params);
    cout << "after computeBplusASPVWOptimized" << endl;

    int rangeToCheck = 850; // range check is from [-rangeToCheck, rangeToCheck-1]
    newRangeCheckPVW(packedSIC, rangeToCheck, relin_keys, degree, context, params);
    cout << "after newRangeCheckPVW" << endl;

    return packedSIC[0];
}

// Phase 1, obtaining PV's based on encrypted targetId
Ciphertext serverOperations1obtainPackedSICWithCluePoly(vector<vector<uint64_t>>& cluePoly, vector<Ciphertext> switchingKey, const RelinKeys& relin_keys,
                            const GaloisKeys& gal_keys, const size_t& degree, const SEALContext& context, const PVWParam& params, const int numOfTransactions){
    Evaluator evaluator(context);
    
    vector<Ciphertext> packedSIC(params.ell);
    computeBplusASPVWOptimizedWithCluePoly(packedSIC, cluePoly, switchingKey, gal_keys, context, params);
    cout << "after computeBplusASPVWOptimized" << endl;

    int rangeToCheck = 850; // range check is from [-rangeToCheck, rangeToCheck-1]
    newRangeCheckPVW(packedSIC, rangeToCheck, relin_keys, degree, context, params);
    cout << "after newRangeCheckPVW" << endl;

    return packedSIC[0];
}

// Phase 2, retrieving
void serverOperations2therest(Ciphertext& lhs, vector<vector<int>>& bipartite_map, Ciphertext& rhs,
                        Ciphertext& packedSIC, const vector<vector<uint64_t>>& payload, const RelinKeys& relin_keys, const GaloisKeys& gal_keys,
                        const size_t& degree, const SEALContext& context, const SEALContext& context2, const PVWParam& params, const int numOfTransactions, 
                        int& counter, int partySize = 1, const int payloadSize = 306){

    Evaluator evaluator(context);
    int step = 32; // simply to save memory so process 32 msgs at a time
    
    bool expandAlter = true;
    
    for(int i = counter; i < counter+numOfTransactions; i += step){
        vector<Ciphertext> expandedSIC;
        // step 1. expand PV
        if(expandAlter)
            expandSIC_Alt(expandedSIC, packedSIC, gal_keys, gal_keys_last, int(degree), context, context2, step, i-counter);
        else
            expandSIC(expandedSIC, packedSIC, gal_keys, gal_keys_last, int(degree), context, context2, step, i-counter);

        // transform to ntt form for better efficiency especially for the last two steps
        for(size_t j = 0; j < expandedSIC.size(); j++)
            if(!expandedSIC[j].is_ntt_form())
                evaluator.transform_to_ntt_inplace(expandedSIC[j]);

        // step 2. deterministic retrieval
        deterministicIndexRetrieval(lhs, expandedSIC, context, degree, i, partySize);

        // step 3-4. multiply weights and pack them
        // The following two steps are for streaming updates
        vector<vector<Ciphertext>> payloadUnpacked;
        payloadRetrievalOptimizedwithWeights(payloadUnpacked, payload, bipartite_map_glb, weights_glb, expandedSIC, context, degree, i, i - counter);
        // Note that if number of repeatitions is already set, this is the only step needed for streaming updates
        payloadPackingOptimized(rhs, payloadUnpacked, bipartite_map_glb, degree, context, gal_keys, i);   
    }
    if(lhs.is_ntt_form())
        evaluator.transform_from_ntt_inplace(lhs);
    if(rhs.is_ntt_form())
        evaluator.transform_from_ntt_inplace(rhs);

    counter += numOfTransactions;
}

// Phase 2, retrieving for OMR3
void serverOperations3therest(vector<Ciphertext>& lhsCounter, vector<vector<int>>& bipartite_map, Ciphertext& rhs,
                        Ciphertext& packedSIC, const vector<vector<uint64_t>>& payload, const RelinKeys& relin_keys, const GaloisKeys& gal_keys, const PublicKey& public_key,
                        const size_t& degree, const SEALContext& context, const SEALContext& context2, const PVWParam& params, const int numOfTransactions, 
                        int& counter, int numberOfCt = 1, int partySize = 1, int slotPerBucket = 3, const int payloadSize = 306){

    Evaluator evaluator(context);

    int step = 32;
    for(int i = counter; i < counter+numOfTransactions; i += step){
        // step 1. expand PV
        vector<Ciphertext> expandedSIC;
        expandSIC_Alt(expandedSIC, packedSIC, gal_keys, gal_keys_last, int(degree), context, context2, step, i-counter);
        // transform to ntt form for better efficiency for all of the following steps
        for(size_t j = 0; j < expandedSIC.size(); j++)
            if(!expandedSIC[j].is_ntt_form())
                evaluator.transform_to_ntt_inplace(expandedSIC[j]);

        // step 2. randomized retrieval
        randomizedIndexRetrieval_opt(lhsCounter, expandedSIC, context, public_key, i, degree, repetition_glb, numberOfCt, 512, partySize, slotPerBucket);
        // step 3-4. multiply weights and pack them
        // The following two steps are for streaming updates
        vector<vector<Ciphertext>> payloadUnpacked;
        payloadRetrievalOptimizedwithWeights(payloadUnpacked, payload, bipartite_map_glb, weights_glb, expandedSIC, context, degree, i, i-counter);
        // Note that if number of repeatitions is already set, this is the only step needed for streaming updates
        payloadPackingOptimized(rhs, payloadUnpacked, bipartite_map_glb, degree, context, gal_keys, i);
    }
    for(size_t i = 0; i < lhsCounter.size(); i++){
            evaluator.transform_from_ntt_inplace(lhsCounter[i]);
    }
    if(rhs.is_ntt_form())
        evaluator.transform_from_ntt_inplace(rhs);
    
    counter += numOfTransactions;
}


vector<vector<long>> receiverDecoding(Ciphertext& lhsEnc, vector<vector<int>>& bipartite_map, Ciphertext& rhsEnc,
                        const size_t& degree, const SecretKey& secret_key, const SEALContext& context, const int numOfTransactions, int partySize = 1,
                        int seed = 3, const int payloadUpperBound = 306, const int payloadSize = 306){

    // 1. find pertinent indices
    map<int, pair<int, int>> pertinentIndices;
    decodeIndices(pertinentIndices, lhsEnc, numOfTransactions, degree, secret_key, context, partySize);
    cout << "Pertinent message indices found with its group PV value: " << endl;
    for (map<int, pair<int, int>>::iterator it = pertinentIndices.begin(); it != pertinentIndices.end(); it++)
    {
        cout << it->first << "," << it->second.second << "  ";
    }
    cout << endl;

    // 2. forming rhs
    vector<vector<int>> rhs;
    vector<Ciphertext> rhsEncVec{rhsEnc};
    formRhs(rhs, rhsEncVec, secret_key, degree, context, OMRtwoM);

    // 3. forming lhs
    vector<vector<int>> lhs;
    formLhsWeights(lhs, pertinentIndices, bipartite_map_glb, weights_glb, 0, OMRtwoM);

    // 4. solving equation
    auto newrhs = equationSolving(lhs, rhs, payloadSize);

    return newrhs;
}

vector<vector<long>> receiverDecodingOMR3(vector<Ciphertext>& lhsCounter, vector<vector<int>>& bipartite_map, Ciphertext& rhsEnc,
                        const size_t& degree, const SecretKey& secret_key, const SEALContext& context, const int numOfTransactions,
                        int partySize = 1, int slot_per_bucket = 3, int seed = 3, const int payloadUpperBound = 306, const int payloadSize = 306){
    // 1. find pertinent indices
    map<int, pair<int, int>> pertinentIndices;
    decodeIndicesRandom_opt(pertinentIndices, lhsCounter, 5, 512, degree, secret_key, context, partySize, slot_per_bucket);
    for (map<int, pair<int, int>>::iterator it = pertinentIndices.begin(); it != pertinentIndices.end(); it++)
    {
        cout << it->first << "," << it->second.second << "  ";
    }
    cout << std::endl;

    // 2. forming rhs
    vector<vector<int>> rhs;
    vector<Ciphertext> rhsEncVec{rhsEnc};
    formRhs(rhs, rhsEncVec, secret_key, degree, context, OMRthreeM);

    // 3. forming lhs
    vector<vector<int>> lhs;
    formLhsWeights(lhs, pertinentIndices, bipartite_map_glb, weights_glb, 0, OMRthreeM);

    // 4. solving equation
    auto newrhs = equationSolving(lhs, rhs, payloadSize);

    return newrhs;
}

// to check whether the result is as expected
bool checkRes(vector<vector<uint64_t>> expected, vector<vector<long>> res){
    for(size_t i = 0; i < expected.size(); i++){
        bool flag = false;
        for(size_t j = 0; j < res.size(); j++){
            if(expected[i][0] == uint64_t(res[j][0])){
                if(expected[i].size() != res[j].size())
                {
                    cerr << "expected and res length not the same" << endl;
                    return false;
                }
                for(size_t k = 1; k < res[j].size(); k++){
                    if(expected[i][k] != uint64_t(res[j][k]))
                        break;
                    if(k == res[j].size() - 1){
                        flag = true;
                    }
                }
            }
        }
        if(!flag)
            return false;
    }
    return true;
}

// check OMD detection key size
// We are:
//      1. packing PVW sk into ell ciphertexts
//      2. using seed mode in SEAL
void OMDlevelspecificDetectKeySize(){
    auto params = PVWParam(450, 65537, 1.3, 16000, 4); 
    auto sk = PVWGenerateSecretKey(params);
    cout << "Finishing generating sk for PVW cts\n";
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = poly_modulus_degree_glb;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    auto coeff_modulus = CoeffModulus::Create(poly_modulus_degree, { 28, 
                                                                            39, 60, 60, 60, 
                                                                            60, 60, 60, 60, 60, 60,
                                                                            32, 30, 60 });
    parms.set_coeff_modulus(coeff_modulus);
    parms.set_plain_modulus(65537);

	prng_seed_type seed;
    for (auto &i : seed)
    {
        i = random_uint64();
    }
    auto rng = make_shared<Blake2xbPRNGFactory>(Blake2xbPRNGFactory(seed));
    parms.set_random_generator(rng);

    SEALContext context(parms, true, sec_level_type::none);
    print_parameters(context); 
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    BatchEncoder batch_encoder(context);
    GaloisKeys gal_keys;

    seal::Serializable<PublicKey> pk = keygen.create_public_key();
	seal::Serializable<RelinKeys> rlk = keygen.create_relin_keys();
	stringstream streamPK, streamRLK, streamRTK;
    auto reskeysize = pk.save(streamPK);
	reskeysize += rlk.save(streamRLK);
	reskeysize += keygen.create_galois_keys(vector<int>({1})).save(streamRTK);

    public_key.load(context, streamPK);
    relin_keys.load(context, streamRLK);
    gal_keys.load(context, streamRTK); 
	vector<seal::Serializable<Ciphertext>>  switchingKeypacked = genSwitchingKeyPVWPacked(context, poly_modulus_degree, public_key, secret_key, sk, params);
	stringstream data_stream;
    for(size_t i = 0; i < switchingKeypacked.size(); i++){
        reskeysize += switchingKeypacked[i].save(data_stream);
    }
    cout << "Detection Key Size: " << reskeysize << " bytes" << endl;
}

// check OMR detection key size
// We are:
//      1. packing PVW sk into ell ciphertexts
//      2. use level-specific rot keys
//      3. using seed mode in SEAL
void levelspecificDetectKeySize(){
    auto params = PVWParam(450, 65537, 1.3, 16000, 4); 
    auto sk = PVWGenerateSecretKey(params);
    cout << "Finishing generating sk for PVW cts\n";

    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = poly_modulus_degree_glb;
    auto degree = poly_modulus_degree;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    auto coeff_modulus = CoeffModulus::Create(poly_modulus_degree, { 28, 
                                                                            60, 60, 60, 60, 60, 
                                                                            60, 60, 60, 60, 60, 60,
                                                                            60, 30, 60 });
    parms.set_coeff_modulus(coeff_modulus);
    parms.set_plain_modulus(65537);


	prng_seed_type seed;
    for (auto &i : seed)
    {
        i = random_uint64();
    }
    auto rng = make_shared<Blake2xbPRNGFactory>(Blake2xbPRNGFactory(seed));
    parms.set_random_generator(rng);

    SEALContext context(parms, true, sec_level_type::none);
    print_parameters(context); 
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    BatchEncoder batch_encoder(context);
    GaloisKeys gal_keys;

    vector<int> steps = {0};
    for(int i = 1; i < int(poly_modulus_degree/2); i *= 2){
	    steps.push_back(i);
    }

    stringstream lvlRTK, lvlRTK2;
    /////////////////////////////////////// Level specific keys
    vector<Modulus> coeff_modulus_next = coeff_modulus;
    coeff_modulus_next.erase(coeff_modulus_next.begin() + 4, coeff_modulus_next.end()-1);
    EncryptionParameters parms_next = parms;
    parms_next.set_coeff_modulus(coeff_modulus_next);
    parms_next.set_random_generator(rng);
    SEALContext context_next = SEALContext(parms_next, true, sec_level_type::none);

    SecretKey sk_next;
    sk_next.data().resize(coeff_modulus_next.size() * degree);
    sk_next.parms_id() = context_next.key_parms_id();
    util::set_poly(secret_key.data().data(), degree, coeff_modulus_next.size() - 1, sk_next.data().data());
    util::set_poly(
        secret_key.data().data() + degree * (coeff_modulus.size() - 1), degree, 1,
        sk_next.data().data() + degree * (coeff_modulus_next.size() - 1));
    KeyGenerator keygen_next(context_next, sk_next); 
    vector<int> steps_next = {0,32,64,128,256,512,1024,2048,4096,8192};
    auto reskeysize = keygen_next.create_galois_keys(steps_next).save(lvlRTK);
        //////////////////////////////////////
    vector<Modulus> coeff_modulus_last = coeff_modulus;
    coeff_modulus_last.erase(coeff_modulus_last.begin() + 3, coeff_modulus_last.end()-1);
    EncryptionParameters parms_last = parms;
    parms_last.set_coeff_modulus(coeff_modulus_last);
    parms_last.set_random_generator(rng);
    SEALContext context_last = SEALContext(parms_last, true, sec_level_type::none);

    SecretKey sk_last;
    sk_last.data().resize(coeff_modulus_last.size() * degree);
    sk_last.parms_id() = context_last.key_parms_id();
    util::set_poly(secret_key.data().data(), degree, coeff_modulus_last.size() - 1, sk_last.data().data());
    util::set_poly(
        secret_key.data().data() + degree * (coeff_modulus.size() - 1), degree, 1,
        sk_last.data().data() + degree * (coeff_modulus_last.size() - 1));
    KeyGenerator keygen_last(context_last, sk_last); 
    vector<int> steps_last = {1,2,4,8,16};
    reskeysize += keygen_last.create_galois_keys(steps_last).save(lvlRTK2);
    //////////////////////////////////////

    seal::Serializable<PublicKey> pk = keygen.create_public_key();
	seal::Serializable<RelinKeys> rlk = keygen.create_relin_keys();
	stringstream streamPK, streamRLK, streamRTK;
    reskeysize += pk.save(streamPK);
	reskeysize += rlk.save(streamRLK);
	reskeysize += keygen.create_galois_keys(vector<int>({1})).save(streamRTK);

    public_key.load(context, streamPK);
    relin_keys.load(context, streamRLK);
    gal_keys.load(context, streamRTK); 
	vector<seal::Serializable<Ciphertext>>  switchingKeypacked = genSwitchingKeyPVWPacked(context, poly_modulus_degree, public_key, secret_key, sk, params);
	stringstream data_stream;
    for(size_t i = 0; i < switchingKeypacked.size(); i++){
        reskeysize += switchingKeypacked[i].save(data_stream);
    }
    cout << "Detection Key Size: " << reskeysize << " bytes" << endl;
}


//////////////////////////////////////////////////// For Oblivious Multiplexer ////////////////////////////////////////////////////


// Pick random values to satisfy multi-variable equation.
// For example, given x + y = 10, we might output {2, 8}.
void assignVariable(vector<vector<long>>& res, vector<int>& lhs, int rhs) {
    if (res.size() != lhs.size())
        cerr << "Coefficient and variable size not match." << endl;

    int lastIndex = lhs.size() - 1;

    for (int i = lhs.size(); i > 0; i--) {
        if (lhs[i-1] != 0) {
            lastIndex = i-1;
            break;
        }
    }

    for (int i = 0; i < lhs.size(); i++) {
        if (lhs[i] != 0 && i != lastIndex) {
            res[i][0] = rand() % 65537;
            rhs = (rhs - (lhs[i] * res[i][0])) % 65537;
        }
    }

    res[lastIndex][0] = div_mod(rhs % 65537, lhs[lastIndex]);
    if (res[lastIndex][0] < 0)
        res[lastIndex][0] += 65537;
}

// Given solved variables with their values, update the remaining equations.
// For example, with equation; x + y + 2z = 10, and z = 2, updated equation would be x + y = 6.
void updateEquation(vector<vector<long>>& res, vector<vector<int>>& lhs, vector<vector<int>>& rhs) {
    for (int i = 0; i < lhs.size(); i++) {
        for (int j = 0; j < res.size(); j++) {
            if (res[j][0] > 0 && lhs[i][j] != 0) {
                rhs[i][0] = (rhs[i][0] - lhs[i][j] * res[j][0]) % 65537;
                lhs[i][j] = 0;
            }
        }
    }
}

// Pick random Zq elements as ID of recipients, in form of a (partySize x idSize) matrix.
vector<vector<int>> initializeRecipientId(int partySize, int idSize, int mod = 65537) {
    vector<vector<int>> ids(partySize, vector<int> (idSize, -1)); 

    for (int i = 0; i < ids.size(); i++) {
        for (int j = 0; j < ids[0].size(); j++) {
            ids[i][j] = rand() % mod;
        }
    }

    return ids;
}

// Read in the a/b[i] part as a 1 x partySize RHS vector for Oblivious Multiplexer polynomial.
void prepareClueRhs(vector<vector<int>>& rhs, const vector<PVWCiphertext> clues, int index, bool prepare = false) {
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

// solve the equation system with rhs to be the clues, and lhs to be the ids via equationSolving
// for non-full rank matrices, rand values are assigned to variables.
vector<vector<long>> solveCluePolynomial(const PVWParam& params, size_t counter, vector<vector<int>> ids, int index, bool prepare = false,
                                         int partySize = party_size_glb, int idSize = id_size_glb) {
    vector<vector<int>> lhs = ids;
    vector<vector<int>> rhs(partySize, vector<int>(1, -1));
    vector<vector<long>> tryRes;
    vector<PVWCiphertext> clues;

    loadClues(clues, counter * partySize, counter * partySize + partySize, params);
    prepareClueRhs(rhs, clues, index, prepare);

    tryRes = equationSolving(lhs, rhs, -1);
    if (tryRes.empty()) {
        tryRes.resize(lhs[0].size(), vector<long>(1));
        while (!lhs.empty()) {
            assignVariable(tryRes, lhs[lhs.size() - 1], rhs[rhs.size() - 1][0]);
            lhs.pop_back();
            rhs.pop_back();
            updateEquation(tryRes, lhs, rhs);
        }
    }
    return tryRes;
}

void verify(const vector<int>& targetId, int index) {
    vector<uint64_t> polyFlat = loadDataSingle(index, "cluePoly", 454 * id_size_glb);
    vector<vector<long>> cluePolynomial(454, vector<long>(id_size_glb));
    vector<long> res(454, 0);

    for (int i = 0; i < 454; i++) {
        for(int j = 0; j < id_size_glb; j++) {
            res[i] = (res[i] + polyFlat[i * id_size_glb + j] * targetId[j]) % 65537;
        }
    }

    cout << "VERIFY ---> " << index << endl;
    cout << res << endl;
}

// similar to preparingTransactionsFormal but for gOMR with Oblivious Multiplexer.
void preparingGroupCluePolynomial(const vector<int>& pertinentMsgIndices, PVWpk& pk, int numOfTransactions,int pertinentMsgNum,
                                  const PVWParam& params, const vector<int>& targetId, bool prepare = false, int clueLength = 454) {
    vector<vector<int>> ids;
    bool check = false;

    cout << pertinentMsgIndices << endl;

    for(int i = 0; i < numOfTransactions; i++){
        if (find(pertinentMsgIndices.begin(), pertinentMsgIndices.end(), i) != pertinentMsgIndices.end()) {
            check = true;
            ids = initializeRecipientId(party_size_glb - 1, id_size_glb);
            ids.push_back(targetId);
        } else {
            ids = initializeRecipientId(party_size_glb, id_size_glb);
        }

        // if i is pertinent for recipient r, then its clue is already generated via given sk, and will be in the same equation
        // i.e., when multiplied the polynomial matrix with the recipient r's ID, detector will get clue i.
        vector<vector<long>> cluePolynomial(clueLength, vector<long>(id_size_glb));
        for (int a = 0; a < clueLength; a++) {
            vector<vector<long>> temp = solveCluePolynomial(params, i, ids, a, prepare);
            for(int j = 0; j < id_size_glb; j++){
                cluePolynomial[a][j] = temp[j][0];
            }
        }
        saveGroupClues(cluePolynomial, i);

        if (check) {
            verify(targetId, i);
            check = false;
        }
    }
}