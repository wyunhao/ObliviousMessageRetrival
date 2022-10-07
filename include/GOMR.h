#include "PVWToBFVSeal.h"
#include "SealUtils.h"
#include "retrieval.h"
#include "client.h"
#include "LoadAndSaveUtils.h"
#include "OMRUtil.h"
#include "MRE.h"
#include <NTL/BasicThreadPool.h>
#include <NTL/ZZ.h>
#include <thread>

using namespace seal;

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////// Ad-hoc Version Group OMR //////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


void GOMR1() {

    size_t poly_modulus_degree = poly_modulus_degree_glb;

    int numOfTransactions = numOfTransactions_glb;
    createDatabase(numOfTransactions, 306);
    cout << "Finishing createDatabase\n";

    // step 1. generate PVW sk
    // recipient side
    auto params = PVWParam(450, 65537, 1.3, 16000, 4);
    auto sk = PVWGenerateSecretKey(params);
    auto pk = PVWGeneratePublicKey(params, sk);
    cout << "Finishing generating sk for PVW cts\n";

    // step 2. prepare transactions
    vector<int> pertinentMsgIndices;
    auto expected = preparingTransactionsFormal(pertinentMsgIndices, pk, numOfTransactions, num_of_pertinent_msgs_glb, params, party_size_glb);
    cout << expected.size() << " pertinent msg: Finishing preparing messages\n";

    // step 3. generate detection key
    // recipient side
    EncryptionParameters parms(scheme_type::bfv);
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
    keygen.create_relin_keys(relin_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    BatchEncoder batch_encoder(context);

    vector<Ciphertext> switchingKey = omr::generateDetectionKey(context, poly_modulus_degree, public_key, secret_key, sk, params);
    Ciphertext packedSIC;

    vector<vector<PVWCiphertext>> SICPVW_multicore(numcores);
    vector<vector<vector<uint64_t>>> payload_multicore(numcores);
    vector<int> counter(numcores);

    GaloisKeys gal_keys;
    vector<int> stepsfirst = {1};
    // only one rot key is needed for full level
    keygen.create_galois_keys(stepsfirst, gal_keys);

    /////////////////////////////////////////////////////////////// Rot Key gen
    vector<int> steps = {0};
    for(int i = 1; i < int(poly_modulus_degree/2); i *= 2){
	    steps.push_back(i);
    }

    cout << "Finishing generating detection keys\n";

    /////////////////////////////////////// Level specific keys
    vector<Modulus> coeff_modulus_next = coeff_modulus;
    coeff_modulus_next.erase(coeff_modulus_next.begin() + 4, coeff_modulus_next.end()-1);
    EncryptionParameters parms_next = parms;
    parms_next.set_coeff_modulus(coeff_modulus_next);
    SEALContext context_next = SEALContext(parms_next, true, sec_level_type::none);

    SecretKey sk_next;
    sk_next.data().resize(coeff_modulus_next.size() * degree);
    sk_next.parms_id() = context_next.key_parms_id();
    util::set_poly(secret_key.data().data(), degree, coeff_modulus_next.size() - 1, sk_next.data().data());
    util::set_poly(
        secret_key.data().data() + degree * (coeff_modulus.size() - 1), degree, 1,
        sk_next.data().data() + degree * (coeff_modulus_next.size() - 1));
    KeyGenerator keygen_next(context_next, sk_next);
    vector<int> steps_next = {0,32,64,128,256,512};
    keygen_next.create_galois_keys(steps_next, gal_keys_next);
        //////////////////////////////////////
    vector<Modulus> coeff_modulus_last = coeff_modulus;
    coeff_modulus_last.erase(coeff_modulus_last.begin() + 3, coeff_modulus_last.end() - 1);
    EncryptionParameters parms_last = parms;
    parms_last.set_coeff_modulus(coeff_modulus_last);
    SEALContext context_last = SEALContext(parms_last, true, sec_level_type::none);

    SecretKey sk_last;
    sk_last.data().resize(coeff_modulus_last.size() * degree);
    sk_last.parms_id() = context_last.key_parms_id();
    util::set_poly(secret_key.data().data(), degree, coeff_modulus_last.size() - 1, sk_last.data().data());
    util::set_poly(
        secret_key.data().data() + degree * (coeff_modulus.size() - 1), degree, 1,
        sk_last.data().data() + degree * (coeff_modulus_last.size() - 1));
    vector<int> steps_last = {1,2,4,8,16};
    KeyGenerator keygen_last(context_last, sk_last);
    keygen_last.create_galois_keys(steps, gal_keys_last);
    //////////////////////////////////////

    vector<vector<Ciphertext>> packedSICfromPhase1(numcores,vector<Ciphertext>(numOfTransactions/numcores/poly_modulus_degree)); // Assume numOfTransactions/numcores/poly_modulus_degree is integer, pad if needed

    NTL::SetNumThreads(numcores);
    SecretKey secret_key_blank;

    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    time_start = chrono::high_resolution_clock::now();

    MemoryPoolHandle my_pool = MemoryPoolHandle::New();
    auto old_prof = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool)));
    NTL_EXEC_RANGE(numcores, first, last);
    for(int i = first; i < last; i++){
        counter[i] = numOfTransactions/numcores*i;

        size_t j = 0;
        while(j < numOfTransactions/numcores/poly_modulus_degree){
            if(!i)
                cout << "Phase 1, Core " << i << ", Batch " << j << endl;

            // divide messages into parties, for partySize ciphertexts, each ciphertext p encrypt the PVs of the p-th messages in all groups
            // sum up all ciphertexts into one, s.t. each slot in the final ciphertext encrypts a single group
            Ciphertext packedSIC_temp;
            for (int p = 0; p < party_size_glb; p++) {
                loadClues(SICPVW_multicore[i], counter[i], counter[i]+poly_modulus_degree, params, p, party_size_glb);

                packedSIC_temp = serverOperations1obtainPackedSIC(SICPVW_multicore[i], switchingKey, relin_keys, gal_keys,
                                                                  poly_modulus_degree, context, params, poly_modulus_degree);
                if (p == 0){
                    packedSICfromPhase1[i][j] = packedSIC_temp;
                } else {
                    evaluator.add_inplace(packedSICfromPhase1[i][j], packedSIC_temp);
                }
            }
            j++;
            counter[i] += poly_modulus_degree;
            SICPVW_multicore[i].clear();
        }
    }

    NTL_EXEC_RANGE_END;
    MemoryManager::SwitchProfile(std::move(old_prof));

    // step 4. detector operations
    vector<Ciphertext> lhs_multi(numcores), rhs_multi(numcores);
    vector<vector<vector<int>>> bipartite_map(numcores);

    for (auto &i : seed_glb) {
        i = random_uint64();
    }

    bipartiteGraphWeightsGeneration(bipartite_map_glb, weights_glb, numOfTransactions, OMRtwoM, repeatition_glb, seed_glb);

    NTL_EXEC_RANGE(numcores, first, last);
    for(int i = first; i < last; i++){
        MemoryPoolHandle my_pool = MemoryPoolHandle::New();
        auto old_prof = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool)));
        size_t j = 0;
        counter[i] = numOfTransactions/numcores*i;

        while(j < numOfTransactions/numcores/poly_modulus_degree){
            if(!i)
                cout << "Phase 2-3, Core " << i << ", Batch " << j << endl;
            loadData(payload_multicore[i], counter[i], counter[i]+poly_modulus_degree);
            Ciphertext templhs, temprhs;
            serverOperations2therest(templhs, bipartite_map[i], temprhs,
                            packedSICfromPhase1[i][j], payload_multicore[i], relin_keys, gal_keys_next,
                            poly_modulus_degree, context_next, context_last, params, poly_modulus_degree, counter[i], party_size_glb);

            if(j == 0){
                lhs_multi[i] = templhs;
                rhs_multi[i] = temprhs;
            } else {
                evaluator.add_inplace(lhs_multi[i], templhs);
                evaluator.add_inplace(rhs_multi[i], temprhs);
            }
            j++;
            payload_multicore[i].clear();
        }

        MemoryManager::SwitchProfile(std::move(old_prof));
    }
    NTL_EXEC_RANGE_END;

    for(int i = 1; i < numcores; i++){
        evaluator.add_inplace(lhs_multi[0], lhs_multi[i]);
        evaluator.add_inplace(rhs_multi[0], rhs_multi[i]);
    }

    while(context.last_parms_id() != lhs_multi[0].parms_id()){
            evaluator.mod_switch_to_next_inplace(rhs_multi[0]);
            evaluator.mod_switch_to_next_inplace(lhs_multi[0]);
        }

    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "\nDetector running time: " << time_diff.count() << "us." << "\n";

    stringstream data_streamdg, data_streamdg2;
    cout << "Digest size: " << rhs_multi[0].save(data_streamdg) + lhs_multi[0].save(data_streamdg2) << " bytes" << endl;

    // step 5. receiver decoding
    bipartiteGraphWeightsGeneration(bipartite_map_glb, weights_glb, numOfTransactions,OMRtwoM,repeatition_glb,seed_glb);
    time_start = chrono::high_resolution_clock::now();
    auto res = receiverDecoding(lhs_multi[0], bipartite_map[0], rhs_multi[0],
                        poly_modulus_degree, secret_key, context, numOfTransactions, party_size_glb);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "\nRecipient running time: " << time_diff.count() << "us." << "\n";

    if(checkRes(expected, res))
        cout << "Result is correct!" << endl;
    else
        cout << "Overflow" << endl;
}

void GOMR2() {

    size_t poly_modulus_degree = poly_modulus_degree_glb;

    int numOfTransactions = numOfTransactions_glb;
    createDatabase(numOfTransactions, 306);
    cout << "Finishing createDatabase\n";

    // step 1. generate PVW sk
    // recipient side
    auto params = PVWParam(450, 65537, 1.3, 16000, 4);
    auto sk = PVWGenerateSecretKey(params);
    auto pk = PVWGeneratePublicKey(params, sk);
    cout << "Finishing generating sk for PVW cts\n";

    // step 2. prepare transactions
    vector<int> pertinentMsgIndices;
    auto expected = preparingTransactionsFormal(pertinentMsgIndices, pk, numOfTransactions, num_of_pertinent_msgs_glb, params, party_size_glb);
    cout << expected.size() << " pertinent msg: Finishing preparing messages\n";

    // step 3. generate detection key
    // recipient side
    EncryptionParameters parms(scheme_type::bfv);
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
    keygen.create_relin_keys(relin_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    BatchEncoder batch_encoder(context);

    vector<Ciphertext> switchingKey = omr::generateDetectionKey(context, poly_modulus_degree, public_key, secret_key, sk, params);
    Ciphertext packedSIC;

    vector<vector<PVWCiphertext>> SICPVW_multicore(numcores);
    vector<vector<vector<uint64_t>>> payload_multicore(numcores);
    vector<int> counter(numcores);

    GaloisKeys gal_keys;
    vector<int> stepsfirst = {1};
    // only one rot key is needed for full level
    keygen.create_galois_keys(stepsfirst, gal_keys);

    /////////////////////////////////////////////////////////////// Rot Key gen
    vector<int> steps = {0};
    for(int i = 1; i < int(poly_modulus_degree/2); i *= 2){
	    steps.push_back(i);
    }

    cout << "Finishing generating detection keys\n";

    /////////////////////////////////////// Level specific keys
    vector<Modulus> coeff_modulus_next = coeff_modulus;
    coeff_modulus_next.erase(coeff_modulus_next.begin() + 4, coeff_modulus_next.end()-1);
    EncryptionParameters parms_next = parms;
    parms_next.set_coeff_modulus(coeff_modulus_next);
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
    keygen_next.create_galois_keys(steps, gal_keys_next);
        //////////////////////////////////////
    vector<Modulus> coeff_modulus_last = coeff_modulus;
    coeff_modulus_last.erase(coeff_modulus_last.begin() + 3, coeff_modulus_last.end()-1);
    EncryptionParameters parms_last = parms;
    parms_last.set_coeff_modulus(coeff_modulus_last);
    SEALContext context_last = SEALContext(parms_last, true, sec_level_type::none);

    SecretKey sk_last;
    sk_last.data().resize(coeff_modulus_last.size() * degree);
    sk_last.parms_id() = context_last.key_parms_id();
    util::set_poly(secret_key.data().data(), degree, coeff_modulus_last.size() - 1, sk_last.data().data());
    util::set_poly(
        secret_key.data().data() + degree * (coeff_modulus.size() - 1), degree, 1,
        sk_last.data().data() + degree * (coeff_modulus_last.size() - 1));
    vector<int> steps_last = {1,2,4,8,16};
    KeyGenerator keygen_last(context_last, sk_last);
    keygen_last.create_galois_keys(steps, gal_keys_last);
    //////////////////////////////////////
    PublicKey public_key_last;
    keygen_next.create_public_key(public_key_last);

    //////////////////////////////////////

    vector<vector<Ciphertext>> packedSICfromPhase1(numcores,vector<Ciphertext>(numOfTransactions/numcores/poly_modulus_degree)); // Assume numOfTransactions/numcores/poly_modulus_degree is integer, pad if needed

    NTL::SetNumThreads(numcores);
    SecretKey secret_key_blank;

    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    time_start = chrono::high_resolution_clock::now();

    MemoryPoolHandle my_pool = MemoryPoolHandle::New();
    auto old_prof = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool)));
    NTL_EXEC_RANGE(numcores, first, last);
    for(int i = first; i < last; i++){
        counter[i] = numOfTransactions/numcores*i;

        size_t j = 0;
        while(j < numOfTransactions/numcores/poly_modulus_degree){
            if(!i)
                cout << "Phase 1, Core " << i << ", Batch " << j << endl;

            // divide messages into parties, for partySize ciphertexts, each ciphertext p encrypt the PVs of the p-th messages in all groups
            // sum up all ciphertexts into one, s.t. each slot in the final ciphertext encrypts a single group
            Ciphertext packedSIC_temp;
            for (int p = 0; p < party_size_glb; p++) {
                loadClues(SICPVW_multicore[i], counter[i], counter[i]+poly_modulus_degree, params, p, party_size_glb);

                packedSIC_temp = serverOperations1obtainPackedSIC(SICPVW_multicore[i], switchingKey, relin_keys, gal_keys,
                                                                  poly_modulus_degree, context, params, poly_modulus_degree);
                if (p == 0){
                    packedSICfromPhase1[i][j] = packedSIC_temp;
                } else {
                    evaluator.add_inplace(packedSICfromPhase1[i][j], packedSIC_temp);
                }
            }
            j++;
            counter[i] += poly_modulus_degree;
            SICPVW_multicore[i].clear();
        }
    }
    NTL_EXEC_RANGE_END;
    MemoryManager::SwitchProfile(std::move(old_prof));

    // step 4. detector operations
    vector<vector<Ciphertext>> lhs_multi_ctr(numcores);
    vector<Ciphertext> rhs_multi(numcores);
    vector<vector<vector<int>>> bipartite_map(numcores);

    for (auto &i : seed_glb) {
        i = random_uint64();
    }
    bipartiteGraphWeightsGeneration(bipartite_map_glb, weights_glb, numOfTransactions, OMRthreeM, repeatition_glb, seed_glb);

    int number_of_ct = ceil(repetition_glb * 4 * 512 / ((poly_modulus_degree_glb / 512 / 4 * 4 * 512) * 1.0));

    NTL_EXEC_RANGE(numcores, first, last);
    for(int i = first; i < last; i++){
        MemoryPoolHandle my_pool = MemoryPoolHandle::New();
        auto old_prof = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool)));
        size_t j = 0;
        counter[i] = numOfTransactions/numcores*i;

        while(j < numOfTransactions/numcores/poly_modulus_degree){
            if(!i)
                cout << "Phase 2-3, Core " << i << ", Batch " << j << endl;
            loadData(payload_multicore[i], counter[i], counter[i]+poly_modulus_degree);
            vector<Ciphertext> templhsctr;
            Ciphertext temprhs;
            serverOperations3therest(templhsctr, bipartite_map[i], temprhs, packedSICfromPhase1[i][j], payload_multicore[i],
                            relin_keys, gal_keys_next, public_key_last, poly_modulus_degree, context_next, context_last,
                            params, poly_modulus_degree, counter[i], number_of_ct, party_size_glb, 4);

            if(j == 0){
                lhs_multi_ctr[i] = templhsctr;
                rhs_multi[i] = temprhs;
            } else {
                for(size_t q = 0; q < lhs_multi_ctr[i].size(); q++){
                    evaluator.add_inplace(lhs_multi_ctr[i][q], templhsctr[q]);
                }
                evaluator.add_inplace(rhs_multi[i], temprhs);
            }
            j++;
            payload_multicore[i].clear();
        }

        MemoryManager::SwitchProfile(std::move(old_prof));
    }
    NTL_EXEC_RANGE_END;

    for(int i = 1; i < numcores; i++){
        for(size_t q = 0; q < lhs_multi_ctr[i].size(); q++){
            evaluator.add_inplace(lhs_multi_ctr[0][q], lhs_multi_ctr[i][q]);
        }
        evaluator.add_inplace(rhs_multi[0], rhs_multi[i]);
    }

    while(context.last_parms_id() != lhs_multi_ctr[0][0].parms_id()){
            for(size_t q = 0; q < lhs_multi_ctr[0].size(); q++){
                evaluator.mod_switch_to_next_inplace(lhs_multi_ctr[0][q]);
            }
            evaluator.mod_switch_to_next_inplace(rhs_multi[0]);
        }

    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "\nDetector running time: " << time_diff.count() << "us." << "\n";

    stringstream data_streamdg, data_streamdg2;
    auto digsize = rhs_multi[0].save(data_streamdg);
    for(size_t q = 0; q < lhs_multi_ctr[0].size(); q++){
        digsize += lhs_multi_ctr[0][q].save(data_streamdg2);
    }
    cout << "Digest size: " << digsize << " bytes" << endl;

    // step 5. receiver decoding
    bipartiteGraphWeightsGeneration(bipartite_map_glb, weights_glb, numOfTransactions, OMRthreeM, repeatition_glb, seed_glb);
    time_start = chrono::high_resolution_clock::now();
    auto res = receiverDecodingOMR3(lhs_multi_ctr[0], bipartite_map[0], rhs_multi[0],
                        poly_modulus_degree, secret_key, context, numOfTransactions, party_size_glb, 4);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "\nRecipient running time: " << time_diff.count() << "us." << "\n";

    if(checkRes(expected, res))
        cout << "Result is correct!" << endl;
    else
        cout << "Overflow" << endl;
    
    for(size_t i = 0; i < res.size(); i++){
    }
}


void GOMR1_ObliviousMultiplexer() {

    size_t poly_modulus_degree = poly_modulus_degree_glb;

    int numOfTransactions = numOfTransactions_glb;
    createDatabase(numOfTransactions, 306);
    cout << "Finishing createDatabase\n";

    // step 1. generate PVW sk
    // recipient side
    auto params = PVWParam(450, 65537, 1.3, 16000, 4);
    auto sk = PVWGenerateSecretKey(params);

    auto pk = PVWGeneratePublicKey(params, sk);
    cout << "Finishing generating sk for PVW cts\n";

    const vector<int> targetId = initializeRecipientId(params, 1, id_size_glb)[0];
    cout << "Recipient Target ID: " << targetId << endl;

    // step 2. prepare transactions
    vector<int> pertinentMsgIndices;
    auto expected = preparingTransactionsFormal(pertinentMsgIndices, pk, numOfTransactions, num_of_pertinent_msgs_glb, params, party_size_glb);
    preparingGroupCluePolynomial(pertinentMsgIndices, pk, numOfTransactions, num_of_pertinent_msgs_glb, params, targetId);

    cout << expected.size() << " pertinent msg: Finishing preparing messages\n";

    // step 3. generate detection key
    // recipient side
    EncryptionParameters parms(scheme_type::bfv);
    auto degree = poly_modulus_degree;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    auto coeff_modulus = CoeffModulus::Create(poly_modulus_degree, { 28,
                                                                            60, 60, 60, 60, 60,
                                                                            60, 60, 60, 60, 60, 60,
                                                                            60, 30, 60 });
    parms.set_coeff_modulus(coeff_modulus);
    parms.set_plain_modulus(params.q);

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
    keygen.create_relin_keys(relin_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    BatchEncoder batch_encoder(context);

    vector<Ciphertext> switchingKey = omr::generateDetectionKey(context, poly_modulus_degree, public_key, secret_key, sk, params);
    Ciphertext packedSIC;

    vector<vector<PVWCiphertext>> SICPVW_multicore(numcores);
    vector<vector<vector<uint64_t>>> payload_multicore(numcores);
    vector<int> counter(numcores);

    GaloisKeys gal_keys;
    vector<int> stepsfirst = {1};
    // only one rot key is needed for full level
    keygen.create_galois_keys(stepsfirst, gal_keys);

    /////////////////////////////////////////////////////////////// Rot Key gen
    vector<int> steps = {0};
    for(int i = 1; i < int(poly_modulus_degree/2); i *= 2){
	    steps.push_back(i);
    }

    cout << "Finishing generating detection keys\n";

    /////////////////////////////////////// Level specific keys
    vector<Modulus> coeff_modulus_next = coeff_modulus;
    coeff_modulus_next.erase(coeff_modulus_next.begin() + 4, coeff_modulus_next.end()-1);
    EncryptionParameters parms_next = parms;
    parms_next.set_coeff_modulus(coeff_modulus_next);
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
    keygen_next.create_galois_keys(steps_next, gal_keys_next);
        //////////////////////////////////////
    vector<Modulus> coeff_modulus_last = coeff_modulus;
    coeff_modulus_last.erase(coeff_modulus_last.begin() + 3, coeff_modulus_last.end() - 1);
    EncryptionParameters parms_last = parms;
    parms_last.set_coeff_modulus(coeff_modulus_last);
    SEALContext context_last = SEALContext(parms_last, true, sec_level_type::none);

    SecretKey sk_last;
    sk_last.data().resize(coeff_modulus_last.size() * degree);
    sk_last.parms_id() = context_last.key_parms_id();
    util::set_poly(secret_key.data().data(), degree, coeff_modulus_last.size() - 1, sk_last.data().data());
    util::set_poly(
        secret_key.data().data() + degree * (coeff_modulus.size() - 1), degree, 1,
        sk_last.data().data() + degree * (coeff_modulus_last.size() - 1));
    vector<int> steps_last = {1,2,4,8,16};
    KeyGenerator keygen_last(context_last, sk_last);
    keygen_last.create_galois_keys(steps, gal_keys_last);
    //////////////////////////////////////

    // Assume numOfTransactions/numcores/poly_modulus_degree is integer, pad if needed
    vector<vector<Ciphertext>> packedSICfromPhase1(numcores,vector<Ciphertext>(numOfTransactions/numcores/poly_modulus_degree));

    NTL::SetNumThreads(numcores);
    SecretKey secret_key_blank;

    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    time_start = chrono::high_resolution_clock::now();

    MemoryPoolHandle my_pool = MemoryPoolHandle::New();
    auto old_prof = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool)));
    NTL_EXEC_RANGE(numcores, first, last);
    for(int i = first; i < last; i++) {
        counter[i] = numOfTransactions/numcores*i;

        size_t j = 0;
        while(j < numOfTransactions/numcores/poly_modulus_degree){
            if(!i)
                cout << "Phase 1, Core " << i << ", Batch " << j << endl;

            // divide messages into parties, for partySize ciphertexts, each ciphertext p encrypt the PVs of the p-th messages in all groups
            // sum up all ciphertexts into one, s.t. each slot in the final ciphertext encrypts a single group
            Ciphertext packedSIC_temp;
            loadObliviousMultiplexerClues(pertinentMsgIndices, SICPVW_multicore[i], targetId, counter[i], counter[i]+poly_modulus_degree, params);
            packedSICfromPhase1[i][j] = serverOperations1obtainPackedSIC(SICPVW_multicore[i], switchingKey, relin_keys, gal_keys,
                                                                poly_modulus_degree, context, params, poly_modulus_degree);
            j++;
            counter[i] += poly_modulus_degree;
            SICPVW_multicore[i].clear();
        }
    }

    NTL_EXEC_RANGE_END;
    MemoryManager::SwitchProfile(std::move(old_prof));

    // step 4. detector operations
    vector<Ciphertext> lhs_multi(numcores), rhs_multi(numcores);
    vector<vector<vector<int>>> bipartite_map(numcores);

    for (auto &i : seed_glb) {
        i = random_uint64();
    }
    bipartiteGraphWeightsGeneration(bipartite_map_glb, weights_glb, numOfTransactions, OMRtwoM, repeatition_glb, seed_glb);

    NTL_EXEC_RANGE(numcores, first, last);
    for(int i = first; i < last; i++) {
        MemoryPoolHandle my_pool = MemoryPoolHandle::New();
        auto old_prof = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool)));
        size_t j = 0;
        counter[i] = numOfTransactions/numcores*i;

        while(j < numOfTransactions/numcores/poly_modulus_degree) {
            if(!i)
                cout << "Phase 2-3, Core " << i << ", Batch " << j << endl;
            loadData(payload_multicore[i], counter[i], counter[i]+poly_modulus_degree);
            Ciphertext templhs, temprhs;
            serverOperations2therest(templhs, bipartite_map[i], temprhs,
                            packedSICfromPhase1[i][j], payload_multicore[i], relin_keys, gal_keys_next,
                            poly_modulus_degree, context_next, context_last, params, poly_modulus_degree, counter[i]);

            if(j == 0){
                lhs_multi[i] = templhs;
                rhs_multi[i] = temprhs;
            } else {
                evaluator.add_inplace(lhs_multi[i], templhs);
                evaluator.add_inplace(rhs_multi[i], temprhs);
            }
            j++;
            payload_multicore[i].clear();
        }

        MemoryManager::SwitchProfile(std::move(old_prof));
    }
    NTL_EXEC_RANGE_END;

    for(int i = 1; i < numcores; i++) {
        evaluator.add_inplace(lhs_multi[0], lhs_multi[i]);
        evaluator.add_inplace(rhs_multi[0], rhs_multi[i]);
    }

    while(context.last_parms_id() != lhs_multi[0].parms_id()) {
        evaluator.mod_switch_to_next_inplace(rhs_multi[0]);
        evaluator.mod_switch_to_next_inplace(lhs_multi[0]);
    }

    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "\nDetector running time: " << time_diff.count() << "us." << "\n";

    stringstream data_streamdg, data_streamdg2;
    cout << "Digest size: " << rhs_multi[0].save(data_streamdg) + lhs_multi[0].save(data_streamdg2) << " bytes" << endl;

    // step 5. receiver decoding
    bipartiteGraphWeightsGeneration(bipartite_map_glb, weights_glb, numOfTransactions,OMRtwoM,repeatition_glb,seed_glb);
    time_start = chrono::high_resolution_clock::now();
    auto res = receiverDecoding(lhs_multi[0], bipartite_map[0], rhs_multi[0],
                        poly_modulus_degree, secret_key, context, numOfTransactions);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "\nRecipient running time: " << time_diff.count() << "us." << "\n";

    if(checkRes(expected, res))
        cout << "Result is correct!" << endl;
    else
        cout << "Overflow" << endl;
}


void GOMR2_ObliviousMultiplexer() {

    size_t poly_modulus_degree = poly_modulus_degree_glb;

    int numOfTransactions = numOfTransactions_glb;
    createDatabase(numOfTransactions, 306);
    cout << "Finishing createDatabase\n";

    // step 1. generate PVW sk
    // recipient side
    auto params = PVWParam(450, 65537, 1.3, 16000, 4);
    auto sk = PVWGenerateSecretKey(params);

    auto pk = PVWGeneratePublicKey(params, sk);
    cout << "Finishing generating sk for PVW cts\n";

    const vector<int> targetId = initializeRecipientId(params, 1, id_size_glb)[0];
    cout << "Recipient Target ID: " << targetId << endl;

    // step 2. prepare transactions
    vector<int> pertinentMsgIndices;
    auto expected = preparingTransactionsFormal(pertinentMsgIndices, pk, numOfTransactions, num_of_pertinent_msgs_glb, params, party_size_glb);
    preparingGroupCluePolynomial(pertinentMsgIndices, pk, numOfTransactions, num_of_pertinent_msgs_glb, params, targetId);

    cout << expected.size() << " pertinent msg: Finishing preparing messages\n";

    // step 3. generate detection key
    // recipient side
    EncryptionParameters parms(scheme_type::bfv);
    auto degree = poly_modulus_degree;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    auto coeff_modulus = CoeffModulus::Create(poly_modulus_degree, { 28,
                                                                            60, 60, 60, 60, 60,
                                                                            60, 60, 60, 60, 60, 60,
                                                                            60, 30, 60 });
    parms.set_coeff_modulus(coeff_modulus);
    parms.set_plain_modulus(params.q);

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
    keygen.create_relin_keys(relin_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    BatchEncoder batch_encoder(context);

    vector<Ciphertext> switchingKey = omr::generateDetectionKey(context, poly_modulus_degree, public_key, secret_key, sk, params);
    Ciphertext packedSIC;

    vector<vector<PVWCiphertext>> SICPVW_multicore(numcores);
    vector<vector<vector<uint64_t>>> payload_multicore(numcores);
    vector<int> counter(numcores);

    GaloisKeys gal_keys;
    vector<int> stepsfirst = {1};
    // only one rot key is needed for full level
    keygen.create_galois_keys(stepsfirst, gal_keys);

    /////////////////////////////////////////////////////////////// Rot Key gen
    vector<int> steps = {0};
    for(int i = 1; i < int(poly_modulus_degree/2); i *= 2){
	    steps.push_back(i);
    }

    cout << "Finishing generating detection keys\n";

    /////////////////////////////////////// Level specific keys
    vector<Modulus> coeff_modulus_next = coeff_modulus;
    coeff_modulus_next.erase(coeff_modulus_next.begin() + 4, coeff_modulus_next.end()-1);
    EncryptionParameters parms_next = parms;
    parms_next.set_coeff_modulus(coeff_modulus_next);
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
    keygen_next.create_galois_keys(steps_next, gal_keys_next);
        //////////////////////////////////////
    vector<Modulus> coeff_modulus_last = coeff_modulus;
    coeff_modulus_last.erase(coeff_modulus_last.begin() + 3, coeff_modulus_last.end() - 1);
    EncryptionParameters parms_last = parms;
    parms_last.set_coeff_modulus(coeff_modulus_last);
    SEALContext context_last = SEALContext(parms_last, true, sec_level_type::none);

    SecretKey sk_last;
    sk_last.data().resize(coeff_modulus_last.size() * degree);
    sk_last.parms_id() = context_last.key_parms_id();
    util::set_poly(secret_key.data().data(), degree, coeff_modulus_last.size() - 1, sk_last.data().data());
    util::set_poly(
        secret_key.data().data() + degree * (coeff_modulus.size() - 1), degree, 1,
        sk_last.data().data() + degree * (coeff_modulus_last.size() - 1));
    vector<int> steps_last = {1,2,4,8,16};
    KeyGenerator keygen_last(context_last, sk_last);
    keygen_last.create_galois_keys(steps, gal_keys_last);
    //////////////////////////////////////
    PublicKey public_key_last;
    keygen_next.create_public_key(public_key_last);

    // Assume numOfTransactions/numcores/poly_modulus_degree is integer, pad if needed
    vector<vector<Ciphertext>> packedSICfromPhase1(numcores,vector<Ciphertext>(numOfTransactions/numcores/poly_modulus_degree));

    NTL::SetNumThreads(numcores);
    SecretKey secret_key_blank;

    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    time_start = chrono::high_resolution_clock::now();

    MemoryPoolHandle my_pool = MemoryPoolHandle::New();
    auto old_prof = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool)));
    NTL_EXEC_RANGE(numcores, first, last);
    for(int i = first; i < last; i++) {
        counter[i] = numOfTransactions/numcores*i;

        size_t j = 0;
        while(j < numOfTransactions/numcores/poly_modulus_degree){
            if(!i)
                cout << "Phase 1, Core " << i << ", Batch " << j << endl;

            // divide messages into parties, for partySize ciphertexts, each ciphertext p encrypt the PVs of the p-th messages in all groups
            // sum up all ciphertexts into one, s.t. each slot in the final ciphertext encrypts a single group
            Ciphertext packedSIC_temp;
            loadObliviousMultiplexerClues(pertinentMsgIndices, SICPVW_multicore[i], targetId, counter[i], counter[i]+poly_modulus_degree, params);
            packedSICfromPhase1[i][j] = serverOperations1obtainPackedSIC(SICPVW_multicore[i], switchingKey, relin_keys, gal_keys,
                                                                poly_modulus_degree, context, params, poly_modulus_degree);
            j++;
            counter[i] += poly_modulus_degree;
            SICPVW_multicore[i].clear();
        }
    }

    NTL_EXEC_RANGE_END;
    MemoryManager::SwitchProfile(std::move(old_prof));

    // step 4. detector operations
    vector<vector<Ciphertext>> lhs_multi_ctr(numcores);
    vector<Ciphertext> rhs_multi(numcores);
    vector<vector<vector<int>>> bipartite_map(numcores);

    for (auto &i : seed_glb) {
        i = random_uint64();
    }
    bipartiteGraphWeightsGeneration(bipartite_map_glb, weights_glb, numOfTransactions, OMRthreeM, repeatition_glb, seed_glb);

    int number_of_ct = ceil(repetition_glb * 3 * 512 / ((poly_modulus_degree_glb / 512 / 3 * 3 * 512) * 1.0));

    NTL_EXEC_RANGE(numcores, first, last);
    for (int i = first; i < last; i++) {
        MemoryPoolHandle my_pool = MemoryPoolHandle::New();
        auto old_prof = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool)));
        size_t j = 0;
        counter[i] = numOfTransactions/numcores*i;

        while (j < numOfTransactions/numcores/poly_modulus_degree) {
            if (!i)
                cout << "Phase 2-3, Core " << i << ", Batch " << j << endl;
            loadData(payload_multicore[i], counter[i], counter[i]+poly_modulus_degree);
            vector<Ciphertext> templhsctr;
            Ciphertext temprhs;
            serverOperations3therest(templhsctr, bipartite_map[i], temprhs, packedSICfromPhase1[i][j], payload_multicore[i],
                            relin_keys, gal_keys_next, public_key_last, poly_modulus_degree, context_next, context_last,
                            params, poly_modulus_degree, counter[i], number_of_ct);

            if (j == 0) {
                lhs_multi_ctr[i] = templhsctr;
                rhs_multi[i] = temprhs;
            } else {
                for (size_t q = 0; q < lhs_multi_ctr[i].size(); q++) {
                    evaluator.add_inplace(lhs_multi_ctr[i][q], templhsctr[q]);
                }
                evaluator.add_inplace(rhs_multi[i], temprhs);
            }
            j++;
            payload_multicore[i].clear();
        }
        MemoryManager::SwitchProfile(std::move(old_prof));
    }
    NTL_EXEC_RANGE_END;

    for (int i = 1; i < numcores; i++) {
        for (size_t q = 0; q < lhs_multi_ctr[i].size(); q++) {
            evaluator.add_inplace(lhs_multi_ctr[0][q], lhs_multi_ctr[i][q]);
        }
        evaluator.add_inplace(rhs_multi[0], rhs_multi[i]);
    }

    while (context.last_parms_id() != lhs_multi_ctr[0][0].parms_id()) {
        for (size_t q = 0; q < lhs_multi_ctr[0].size(); q++) {
            evaluator.mod_switch_to_next_inplace(lhs_multi_ctr[0][q]);
        }
        evaluator.mod_switch_to_next_inplace(rhs_multi[0]);
    }

    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "\nDetector running time: " << time_diff.count() << "us." << "\n";

    stringstream data_streamdg, data_streamdg2;
    auto digsize = rhs_multi[0].save(data_streamdg);
    for (size_t q = 0; q < lhs_multi_ctr[0].size(); q++) {
        digsize += lhs_multi_ctr[0][q].save(data_streamdg2);
    }
    cout << "Digest size: " << digsize << " bytes" << endl;

    // step 5. receiver decoding
    bipartiteGraphWeightsGeneration(bipartite_map_glb, weights_glb, numOfTransactions, OMRthreeM, repeatition_glb, seed_glb);
    time_start = chrono::high_resolution_clock::now();
    auto res = receiverDecodingOMR3(lhs_multi_ctr[0], bipartite_map[0], rhs_multi[0],
                        poly_modulus_degree, secret_key, context, numOfTransactions);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "\nRecipient running time: " << time_diff.count() << "us." << "\n";

    if (checkRes(expected, res))
        cout << "Result is correct!" << endl;
    else
        cout << "Overflow" << endl;
}



void GOMR1_ObliviousMultiplexer_BFV() {

    size_t poly_modulus_degree = poly_modulus_degree_glb;

    int numOfTransactions = numOfTransactions_glb;
    createDatabase(numOfTransactions, 306);
    cout << "Finishing createDatabase\n";

    // step 1. generate PVW sk
    // recipient side
    auto params = PVWParam(450, 65537, 1.3, 16000, 4);
    auto sk = PVWGenerateSecretKey(params);
    auto pk = PVWGeneratePublicKey(params, sk);
    cout << "Finishing generating sk for PVW cts\n";

    const vector<int> targetId = initializeRecipientId(params, 1, id_size_glb)[0];
    cout << "Recipient Target ID: " << targetId << endl;

    // step 2. prepare transactions
    vector<int> pertinentMsgIndices;
    auto expected = preparingTransactionsFormal(pertinentMsgIndices, pk, numOfTransactions, num_of_pertinent_msgs_glb, params, party_size_glb);
    preparingGroupCluePolynomial(pertinentMsgIndices, pk, numOfTransactions, num_of_pertinent_msgs_glb, params, targetId, true);

    cout << expected.size() << " pertinent msg: Finishing preparing messages\n";

    // step 3. generate detection key
    // recipient side
    EncryptionParameters parms(scheme_type::bfv);
    auto degree = poly_modulus_degree;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    auto coeff_modulus = CoeffModulus::Create(poly_modulus_degree, { 28,
                                                                            60, 60, 60, 60, 60,
                                                                            60, 60, 60, 60, 60, 60,
                                                                            60, 60, 60 });
    parms.set_coeff_modulus(coeff_modulus);
    parms.set_plain_modulus(65537);

    prng_seed_type seed;
    for (auto &i : seed) {
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
    keygen.create_relin_keys(relin_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    BatchEncoder batch_encoder(context);

    vector<Ciphertext> switchingKey = agomr::generateDetectionKey(targetId, context, poly_modulus_degree, public_key, secret_key, sk, params);
    Ciphertext packedSIC;

    vector<vector<PVWCiphertext>> SICPVW_multicore(numcores);
    vector<vector<vector<uint64_t>>> payload_multicore(numcores);
    vector<int> counter(numcores);

    GaloisKeys gal_keys;
    vector<int> stepsfirst = {1};
    // only one rot key is needed for full level
    keygen.create_galois_keys(stepsfirst, gal_keys);

    /////////////////////////////////////////////////////////////// Rot Key gen
    vector<int> steps = {0};
    for(int i = 1; i < int(poly_modulus_degree/2); i *= 2){
	    steps.push_back(i);
    }

    cout << "Finishing generating detection keys\n";

    /////////////////////////////////////// Level specific keys
    vector<Modulus> coeff_modulus_next = coeff_modulus;
    coeff_modulus_next.erase(coeff_modulus_next.begin() + 4, coeff_modulus_next.end()-1);
    EncryptionParameters parms_next = parms;
    parms_next.set_coeff_modulus(coeff_modulus_next);
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
    keygen_next.create_galois_keys(steps_next, gal_keys_next);
        //////////////////////////////////////
    vector<Modulus> coeff_modulus_last = coeff_modulus;
    coeff_modulus_last.erase(coeff_modulus_last.begin() + 3, coeff_modulus_last.end() - 1);
    EncryptionParameters parms_last = parms;
    parms_last.set_coeff_modulus(coeff_modulus_last);
    SEALContext context_last = SEALContext(parms_last, true, sec_level_type::none);

    SecretKey sk_last;
    sk_last.data().resize(coeff_modulus_last.size() * degree);
    sk_last.parms_id() = context_last.key_parms_id();
    util::set_poly(secret_key.data().data(), degree, coeff_modulus_last.size() - 1, sk_last.data().data());
    util::set_poly(
        secret_key.data().data() + degree * (coeff_modulus.size() - 1), degree, 1,
        sk_last.data().data() + degree * (coeff_modulus_last.size() - 1));
    vector<int> steps_last = {1,2,4,8,16};
    KeyGenerator keygen_last(context_last, sk_last);
    keygen_last.create_galois_keys(steps, gal_keys_last);


    //////////////////////////////////////

    // Assume numOfTransactions/numcores/poly_modulus_degree is integer, pad if needed
    vector<vector<Ciphertext>> packedSICfromPhase1(numcores,vector<Ciphertext>(numOfTransactions/numcores/poly_modulus_degree));
    vector<vector<vector<uint64_t>>> cluePolyMatrics(numcores);

    NTL::SetNumThreads(numcores);
    SecretKey secret_key_blank;

    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    time_start = chrono::high_resolution_clock::now();

    MemoryPoolHandle my_pool = MemoryPoolHandle::New();
    auto old_prof = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool)));
    NTL_EXEC_RANGE(numcores, first, last);
    for(int i = first; i < last; i++) {
        counter[i] = numOfTransactions/numcores*i;

        size_t j = 0;
        while(j < numOfTransactions/numcores/poly_modulus_degree){
            if(!i)
                cout << "Phase 1, Core " << i << ", Batch " << j << endl;

            // divide messages into parties, for partySize ciphertexts, each ciphertext p encrypt the PVs of the p-th messages in all groups
            // sum up all ciphertexts into one, s.t. each slot in the final ciphertext encrypts a single group
            Ciphertext packedSIC_temp;
            loadData(cluePolyMatrics[i], counter[i], counter[i]+poly_modulus_degree, "cluePoly", 454 * id_size_glb);
            packedSICfromPhase1[i][j] = serverOperations1obtainPackedSICWithCluePoly(cluePolyMatrics[i], switchingKey, relin_keys, gal_keys,
                                                                poly_modulus_degree, context, params, poly_modulus_degree);
            j++;
            counter[i] += poly_modulus_degree;
            SICPVW_multicore[i].clear();
        }
    }

    NTL_EXEC_RANGE_END;
    MemoryManager::SwitchProfile(std::move(old_prof));

    // step 4. detector operations
    vector<Ciphertext> lhs_multi(numcores), rhs_multi(numcores);
    vector<vector<vector<int>>> bipartite_map(numcores);

    for (auto &i : seed_glb) {
        i = random_uint64();
    }
    bipartiteGraphWeightsGeneration(bipartite_map_glb, weights_glb, numOfTransactions, OMRtwoM, repeatition_glb, seed_glb);

    NTL_EXEC_RANGE(numcores, first, last);
    for(int i = first; i < last; i++) {
        MemoryPoolHandle my_pool = MemoryPoolHandle::New();
        auto old_prof = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool)));
        size_t j = 0;
        counter[i] = numOfTransactions/numcores*i;

        while(j < numOfTransactions/numcores/poly_modulus_degree) {
            if(!i)
                cout << "Phase 2-3, Core " << i << ", Batch " << j << endl;
            loadData(payload_multicore[i], counter[i], counter[i]+poly_modulus_degree);
            Ciphertext templhs, temprhs;
            serverOperations2therest(templhs, bipartite_map[i], temprhs,
                            packedSICfromPhase1[i][j], payload_multicore[i], relin_keys, gal_keys_next,
                            poly_modulus_degree, context_next, context_last, params, poly_modulus_degree, counter[i]);

            if(j == 0){
                lhs_multi[i] = templhs;
                rhs_multi[i] = temprhs;
            } else {
                evaluator.add_inplace(lhs_multi[i], templhs);
                evaluator.add_inplace(rhs_multi[i], temprhs);
            }
            j++;
            payload_multicore[i].clear();
        }

        MemoryManager::SwitchProfile(std::move(old_prof));
    }
    NTL_EXEC_RANGE_END;

    for(int i = 1; i < numcores; i++) {
        evaluator.add_inplace(lhs_multi[0], lhs_multi[i]);
        evaluator.add_inplace(rhs_multi[0], rhs_multi[i]);
    }

    while(context.last_parms_id() != lhs_multi[0].parms_id()) {
        evaluator.mod_switch_to_next_inplace(rhs_multi[0]);
        evaluator.mod_switch_to_next_inplace(lhs_multi[0]);
    }

    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "\nDetector running time: " << time_diff.count() << "us." << "\n";

    stringstream data_streamdg, data_streamdg2;
    cout << "Digest size: " << rhs_multi[0].save(data_streamdg) + lhs_multi[0].save(data_streamdg2) << " bytes" << endl;

    // step 5. receiver decoding
    bipartiteGraphWeightsGeneration(bipartite_map_glb, weights_glb, numOfTransactions,OMRtwoM,repeatition_glb,seed_glb);
    time_start = chrono::high_resolution_clock::now();
    auto res = receiverDecoding(lhs_multi[0], bipartite_map[0], rhs_multi[0],
                        poly_modulus_degree, secret_key, context, numOfTransactions);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "\nRecipient running time: " << time_diff.count() << "us." << "\n";

    if(checkRes(expected, res))
        cout << "Result is correct!" << endl;
    else
        cout << "Overflow" << endl;
}


void GOMR2_ObliviousMultiplexer_BFV() {

    size_t poly_modulus_degree = poly_modulus_degree_glb;

    int numOfTransactions = numOfTransactions_glb;
    createDatabase(numOfTransactions, 306);
    cout << "Finishing createDatabase\n";

    // step 1. generate PVW sk
    // recipient side
    auto params = PVWParam(450, 65537, 1.3, 16000, 4);
    auto sk = PVWGenerateSecretKey(params);
    auto pk = PVWGeneratePublicKey(params, sk);
    cout << "Finishing generating sk for PVW cts\n";

    const vector<int> targetId = initializeRecipientId(params, 1, id_size_glb)[0];
    cout << "Recipient Target ID: " << targetId << endl;

    // step 2. prepare transactions
    vector<int> pertinentMsgIndices;
    auto expected = preparingTransactionsFormal(pertinentMsgIndices, pk, numOfTransactions, num_of_pertinent_msgs_glb, params, party_size_glb);
    preparingGroupCluePolynomial(pertinentMsgIndices, pk, numOfTransactions, num_of_pertinent_msgs_glb, params, targetId, true);

    cout << expected.size() << " pertinent msg: Finishing preparing messages\n";

    // step 3. generate detection key
    // recipient side
    EncryptionParameters parms(scheme_type::bfv);
    auto degree = poly_modulus_degree;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    auto coeff_modulus = CoeffModulus::Create(poly_modulus_degree, { 28,
                                                                            60, 60, 60, 60, 60,
                                                                            60, 60, 60, 60, 60, 60,
                                                                            60, 60, 60 });
    parms.set_coeff_modulus(coeff_modulus);
    parms.set_plain_modulus(65537);

    prng_seed_type seed;
    for (auto &i : seed) {
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
    keygen.create_relin_keys(relin_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    BatchEncoder batch_encoder(context);

    vector<Ciphertext> switchingKey = agomr::generateDetectionKey(targetId, context, poly_modulus_degree, public_key, secret_key, sk, params);
    Ciphertext packedSIC;

    vector<vector<PVWCiphertext>> SICPVW_multicore(numcores);
    vector<vector<vector<uint64_t>>> payload_multicore(numcores);
    vector<int> counter(numcores);

    GaloisKeys gal_keys;
    vector<int> stepsfirst = {1};
    // only one rot key is needed for full level
    keygen.create_galois_keys(stepsfirst, gal_keys);

    /////////////////////////////////////////////////////////////// Rot Key gen
    vector<int> steps = {0};
    for(int i = 1; i < int(poly_modulus_degree/2); i *= 2){
	    steps.push_back(i);
    }

    cout << "Finishing generating detection keys\n";

    /////////////////////////////////////// Level specific keys
    vector<Modulus> coeff_modulus_next = coeff_modulus;
    coeff_modulus_next.erase(coeff_modulus_next.begin() + 4, coeff_modulus_next.end()-1);
    EncryptionParameters parms_next = parms;
    parms_next.set_coeff_modulus(coeff_modulus_next);
    SEALContext context_next = SEALContext(parms_next, true, sec_level_type::none);

    SecretKey sk_next;
    sk_next.data().resize(coeff_modulus_next.size() * degree);
    sk_next.parms_id() = context_next.key_parms_id();
    util::set_poly(secret_key.data().data(), degree, coeff_modulus_next.size() - 1, sk_next.data().data());
    util::set_poly(
        secret_key.data().data() + degree * (coeff_modulus.size() - 1), degree, 1,
        sk_next.data().data() + degree * (coeff_modulus_next.size() - 1));
    KeyGenerator keygen_next(context_next, sk_next);
    vector<int> steps_next = {0,32,64,128,256,512};
    keygen_next.create_galois_keys(steps_next, gal_keys_next);
        //////////////////////////////////////
    vector<Modulus> coeff_modulus_last = coeff_modulus;
    coeff_modulus_last.erase(coeff_modulus_last.begin() + 3, coeff_modulus_last.end() - 1);
    EncryptionParameters parms_last = parms;
    parms_last.set_coeff_modulus(coeff_modulus_last);
    SEALContext context_last = SEALContext(parms_last, true, sec_level_type::none);

    SecretKey sk_last;
    sk_last.data().resize(coeff_modulus_last.size() * degree);
    sk_last.parms_id() = context_last.key_parms_id();
    util::set_poly(secret_key.data().data(), degree, coeff_modulus_last.size() - 1, sk_last.data().data());
    util::set_poly(
        secret_key.data().data() + degree * (coeff_modulus.size() - 1), degree, 1,
        sk_last.data().data() + degree * (coeff_modulus_last.size() - 1));
    vector<int> steps_last = {1,2,4,8,16};
    KeyGenerator keygen_last(context_last, sk_last);
    keygen_last.create_galois_keys(steps, gal_keys_last);
    //////////////////////////////////////
    PublicKey public_key_last;
    keygen_next.create_public_key(public_key_last);

    // Assume numOfTransactions/numcores/poly_modulus_degree is integer, pad if needed
    vector<vector<Ciphertext>> packedSICfromPhase1(numcores,vector<Ciphertext>(numOfTransactions/numcores/poly_modulus_degree));
    vector<vector<vector<uint64_t>>> cluePolyMatrics(numcores);

    NTL::SetNumThreads(numcores);
    SecretKey secret_key_blank;

    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    time_start = chrono::high_resolution_clock::now();

    MemoryPoolHandle my_pool = MemoryPoolHandle::New();
    auto old_prof = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool)));
    NTL_EXEC_RANGE(numcores, first, last);
    for(int i = first; i < last; i++) {
        counter[i] = numOfTransactions/numcores*i;

        size_t j = 0;
        while(j < numOfTransactions/numcores/poly_modulus_degree){
            if(!i)
                cout << "Phase 1, Core " << i << ", Batch " << j << endl;

            // divide messages into parties, for partySize ciphertexts, each ciphertext p encrypt the PVs of the p-th messages in all groups
            // sum up all ciphertexts into one, s.t. each slot in the final ciphertext encrypts a single group
            Ciphertext packedSIC_temp;
            loadData(cluePolyMatrics[i], counter[i], counter[i]+poly_modulus_degree, "cluePoly", 454 * id_size_glb);
            packedSICfromPhase1[i][j] = serverOperations1obtainPackedSICWithCluePoly(cluePolyMatrics[i], switchingKey, relin_keys, gal_keys,
                                                                poly_modulus_degree, context, params, poly_modulus_degree);
            j++;
            counter[i] += poly_modulus_degree;
            SICPVW_multicore[i].clear();
        }
    }

    NTL_EXEC_RANGE_END;
    MemoryManager::SwitchProfile(std::move(old_prof));
    
    // step 4. detector operations
    vector<vector<Ciphertext>> lhs_multi_ctr(numcores);
    vector<Ciphertext> rhs_multi(numcores);
    vector<vector<vector<int>>> bipartite_map(numcores);

    for (auto &i : seed_glb) {
        i = random_uint64();
    }
    bipartiteGraphWeightsGeneration(bipartite_map_glb, weights_glb, numOfTransactions, OMRthreeM, repeatition_glb, seed_glb);

    int number_of_ct = ceil(repetition_glb * 3 * 512 / ((poly_modulus_degree_glb / 512 / 3 * 3 * 512) * 1.0));

    NTL_EXEC_RANGE(numcores, first, last);
    for (int i = first; i < last; i++) {
        MemoryPoolHandle my_pool = MemoryPoolHandle::New();
        auto old_prof = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool)));
        size_t j = 0;
        counter[i] = numOfTransactions/numcores*i;

        while (j < numOfTransactions/numcores/poly_modulus_degree) {
            if (!i)
                cout << "Phase 2-3, Core " << i << ", Batch " << j << endl;
            loadData(payload_multicore[i], counter[i], counter[i]+poly_modulus_degree);
            vector<Ciphertext> templhsctr;
            Ciphertext temprhs;
            serverOperations3therest(templhsctr, bipartite_map[i], temprhs, packedSICfromPhase1[i][j], payload_multicore[i],
                            relin_keys, gal_keys_next, public_key_last, poly_modulus_degree, context_next, context_last,
                            params, poly_modulus_degree, counter[i], number_of_ct);

            if (j == 0) {
                lhs_multi_ctr[i] = templhsctr;
                rhs_multi[i] = temprhs;
            } else {
                for (size_t q = 0; q < lhs_multi_ctr[i].size(); q++) {
                    evaluator.add_inplace(lhs_multi_ctr[i][q], templhsctr[q]);
                }
                evaluator.add_inplace(rhs_multi[i], temprhs);
            }
            j++;
            payload_multicore[i].clear();
        }
        MemoryManager::SwitchProfile(std::move(old_prof));
    }
    NTL_EXEC_RANGE_END;

    for (int i = 1; i < numcores; i++) {
        for (size_t q = 0; q < lhs_multi_ctr[i].size(); q++) {
            evaluator.add_inplace(lhs_multi_ctr[0][q], lhs_multi_ctr[i][q]);
        }
        evaluator.add_inplace(rhs_multi[0], rhs_multi[i]);
    }

    while (context.last_parms_id() != lhs_multi_ctr[0][0].parms_id()) {
        for (size_t q = 0; q < lhs_multi_ctr[0].size(); q++) {
            evaluator.mod_switch_to_next_inplace(lhs_multi_ctr[0][q]);
        }
        evaluator.mod_switch_to_next_inplace(rhs_multi[0]);
    }

    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "\nDetector running time: " << time_diff.count() << "us." << "\n";

    stringstream data_streamdg, data_streamdg2;
    auto digsize = rhs_multi[0].save(data_streamdg);
    for (size_t q = 0; q < lhs_multi_ctr[0].size(); q++) {
        digsize += lhs_multi_ctr[0][q].save(data_streamdg2);
    }
    cout << "Digest size: " << digsize << " bytes" << endl;

    // step 5. receiver decoding
    bipartiteGraphWeightsGeneration(bipartite_map_glb, weights_glb, numOfTransactions, OMRthreeM, repeatition_glb, seed_glb);
    time_start = chrono::high_resolution_clock::now();
    auto res = receiverDecodingOMR3(lhs_multi_ctr[0], bipartite_map[0], rhs_multi[0],
                        poly_modulus_degree, secret_key, context, numOfTransactions);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "\nRecipient running time: " << time_diff.count() << "us." << "\n";

    if (checkRes(expected, res))
        cout << "Result is correct!" << endl;
    else
        cout << "Overflow" << endl;
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////// Fixed Group Version Group OMR ///////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void GOMR1_FG() {
    size_t poly_modulus_degree = poly_modulus_degree_glb;

    int numOfTransactions = numOfTransactions_glb;
    createDatabase(numOfTransactions, 306);
    cout << "Finishing createDatabase\n";

    // step 1. generate MRE sk
    // recipient side
    prng_seed_type mreseed;
    for (auto &i : mreseed) {
        i = random_uint64();
    }

    auto params = PVWParam(450 + partial_size_glb, 65537, 1.3, 16000, 4);
    vector<fgomr::FixedGroupSecretKey> groupSK = fgomr::secretKeyGen(params);
    fgomr::FixedGroupSharedKey partialPK = fgomr::groupKeyGenAux(params, groupSK, mreseed);
    fgomr::FixedGroupPublicKey groupPK = fgomr::keyGen(params, partialPK, mreseed);
    cout << "Finishing generating pk for targeted recipient group\n";

    // step 2. prepare transactions
    vector<int> pertinentMsgIndices;
    auto expected = preparingMREGroupClue(pertinentMsgIndices, groupPK, numOfTransactions, num_of_pertinent_msgs_glb, params, mreseed);
    cout << expected.size() << " pertinent msg: Finishing preparing messages with indices: " << pertinentMsgIndices << endl;

    // step 3. generate detection key
    // recipient side
    EncryptionParameters parms(scheme_type::bfv);
    auto degree = poly_modulus_degree;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    auto coeff_modulus = CoeffModulus::Create(poly_modulus_degree, { 28,
                                                                            60, 60, 60, 60, 60,
                                                                            60, 60, 60, 60, 60, 60,
                                                                            60, 30, 60 });
    parms.set_coeff_modulus(coeff_modulus);
    parms.set_plain_modulus(params.q);

    prng_seed_type seed;
    for (auto &i : seed) {
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
    keygen.create_relin_keys(relin_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    BatchEncoder batch_encoder(context);

    // w.l.o.g, use the first member in the group to test, ideally, any one should be able to detect same pertinent messages
    fgomr::FixedGroupDetectionKey switchingKey = fgomr::generateDetectionKey(params, context, poly_modulus_degree, public_key, secret_key, groupSK[4]);
    Ciphertext packedSIC;

    vector<vector<PVWCiphertext>> SICPVW_multicore(numcores);
    vector<vector<vector<uint64_t>>> payload_multicore(numcores);
    vector<int> counter(numcores);

    GaloisKeys gal_keys;
    vector<int> stepsfirst = {1};
    // only one rot key is needed for full level
    keygen.create_galois_keys(stepsfirst, gal_keys);

    /////////////////////////////////////////////////////////////// Rot Key gen
    vector<int> steps = {0};
    for(int i = 1; i < int(poly_modulus_degree/2); i *= 2) {
	    steps.push_back(i);
    }

    cout << "Finishing generating detection keys\n";

    /////////////////////////////////////// Level specific keys
    vector<Modulus> coeff_modulus_next = coeff_modulus;
    coeff_modulus_next.erase(coeff_modulus_next.begin() + 4, coeff_modulus_next.end()-1);
    EncryptionParameters parms_next = parms;
    parms_next.set_coeff_modulus(coeff_modulus_next);
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
    keygen_next.create_galois_keys(steps_next, gal_keys_next);

    //////////////////////////////////////
    vector<Modulus> coeff_modulus_last = coeff_modulus;
    coeff_modulus_last.erase(coeff_modulus_last.begin() + 3, coeff_modulus_last.end()-1);
    EncryptionParameters parms_last = parms;
    parms_last.set_coeff_modulus(coeff_modulus_last);
    SEALContext context_last = SEALContext(parms_last, true, sec_level_type::none);

    SecretKey sk_last;
    sk_last.data().resize(coeff_modulus_last.size() * degree);
    sk_last.parms_id() = context_last.key_parms_id();
    util::set_poly(secret_key.data().data(), degree, coeff_modulus_last.size() - 1, sk_last.data().data());
    util::set_poly(
        secret_key.data().data() + degree * (coeff_modulus.size() - 1), degree, 1,
        sk_last.data().data() + degree * (coeff_modulus_last.size() - 1));
    vector<int> steps_last = {1,2,4,8,16};
    KeyGenerator keygen_last(context_last, sk_last);
    keygen_last.create_galois_keys(steps, gal_keys_last);
    //////////////////////////////////////

    vector<vector<Ciphertext>> packedSICfromPhase1(numcores,vector<Ciphertext>(numOfTransactions/numcores/poly_modulus_degree)); // Assume numOfTransactions/numcores/poly_modulus_degree is integer, pad if needed

    NTL::SetNumThreads(numcores);
    SecretKey secret_key_blank;

    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    time_start = chrono::high_resolution_clock::now();

    MemoryPoolHandle my_pool = MemoryPoolHandle::New();
    auto old_prof = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool)));
    NTL_EXEC_RANGE(numcores, first, last);
    for (int i = first; i < last; i++) {
        counter[i] = numOfTransactions/numcores*i;

        size_t j = 0;
        while(j < numOfTransactions/numcores/poly_modulus_degree) {
            if (!i)
                cout << "Phase 1, Core " << i << ", Batch " << j << endl;
            loadClues(SICPVW_multicore[i], counter[i], counter[i]+poly_modulus_degree, params);
            packedSICfromPhase1[i][j] = serverOperations1obtainPackedSIC(SICPVW_multicore[i], switchingKey, relin_keys, gal_keys,
                                                            poly_modulus_degree, context, params, poly_modulus_degree);
            j++;
            counter[i] += poly_modulus_degree;
            SICPVW_multicore[i].clear();
        }
    }
    NTL_EXEC_RANGE_END;
    MemoryManager::SwitchProfile(std::move(old_prof));

    // step 4. detector operations
    vector<Ciphertext> lhs_multi(numcores), rhs_multi(numcores);
    vector<vector<vector<int>>> bipartite_map(numcores);

    for (auto &i : seed_glb) {
        i = random_uint64();
    }
    bipartiteGraphWeightsGeneration(bipartite_map_glb, weights_glb, numOfTransactions, OMRtwoM, repeatition_glb, seed_glb);

    NTL_EXEC_RANGE(numcores, first, last);
    for (int i = first; i < last; i++) {
        MemoryPoolHandle my_pool = MemoryPoolHandle::New();
        auto old_prof = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool)));
        size_t j = 0;
        counter[i] = numOfTransactions/numcores*i;

        while (j < numOfTransactions/numcores/poly_modulus_degree) {
            if(!i)
                cout << "Phase 2-3, Core " << i << ", Batch " << j << endl;
            loadData(payload_multicore[i], counter[i], counter[i]+poly_modulus_degree);
            Ciphertext templhs, temprhs;
            serverOperations2therest(templhs, bipartite_map[i], temprhs,
                            packedSICfromPhase1[i][j], payload_multicore[i], relin_keys, gal_keys_next,
                            poly_modulus_degree, context_next, context_last, params, poly_modulus_degree, counter[i]);
            if (j == 0) {
                lhs_multi[i] = templhs;
                rhs_multi[i] = temprhs;
            } else {
                evaluator.add_inplace(lhs_multi[i], templhs);
                evaluator.add_inplace(rhs_multi[i], temprhs);
            }
            j++;
            payload_multicore[i].clear();
        }
        MemoryManager::SwitchProfile(std::move(old_prof));
    }
    NTL_EXEC_RANGE_END;

    for (int i = 1; i < numcores; i++) {
        evaluator.add_inplace(lhs_multi[0], lhs_multi[i]);
        evaluator.add_inplace(rhs_multi[0], rhs_multi[i]);
    }

    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "\nDetector running time: " << time_diff.count() << "us." << "\n";

    stringstream data_streamdg, data_streamdg2;
    cout << "Digest size: " << rhs_multi[0].save(data_streamdg) + lhs_multi[0].save(data_streamdg2) << " bytes" << endl;

    // step 5. receiver decoding
    bipartiteGraphWeightsGeneration(bipartite_map_glb, weights_glb, numOfTransactions,OMRtwoM,repeatition_glb,seed_glb);
    time_start = chrono::high_resolution_clock::now();
    auto res = receiverDecoding(lhs_multi[0], bipartite_map[0], rhs_multi[0],
                        poly_modulus_degree, secret_key, context, numOfTransactions);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "\nRecipient running time: " << time_diff.count() << "us." << "\n";

    if (checkRes(expected, res))
        cout << "Result is correct!" << endl;
    else
        cout << "Overflow" << endl << res << endl;
}


void GOMR2_FG() {
    size_t poly_modulus_degree = poly_modulus_degree_glb;

    int numOfTransactions = numOfTransactions_glb;
    createDatabase(numOfTransactions, 306);
    cout << "Finishing createDatabase\n";

    // step 1. generate MRE sk
    // recipient side
    prng_seed_type mreseed;
    for (auto &i : mreseed) {
        i = random_uint64();
    }

    auto params = PVWParam(450 + partial_size_glb, 65537, 1.3, 16000, 4);
    vector<fgomr::FixedGroupSecretKey> groupSK = fgomr::secretKeyGen(params);
    fgomr::FixedGroupSharedKey partialPK = fgomr::groupKeyGenAux(params, groupSK, mreseed);
    fgomr::FixedGroupPublicKey groupPK = fgomr::keyGen(params, partialPK, mreseed);
    cout << "Finishing generating pk for targeted recipient group\n";

    // step 2. prepare transactions
    vector<int> pertinentMsgIndices;
    auto expected = preparingMREGroupClue(pertinentMsgIndices, groupPK, numOfTransactions, num_of_pertinent_msgs_glb, params, mreseed);
    cout << expected.size() << " pertinent msg: Finishing preparing messages with indices: " << pertinentMsgIndices << endl;

    // step 3. generate detection key
    // recipient side
    EncryptionParameters parms(scheme_type::bfv);
    auto degree = poly_modulus_degree;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    auto coeff_modulus = CoeffModulus::Create(poly_modulus_degree, { 28,
                                                                            60, 60, 60, 60, 60,
                                                                            60, 60, 60, 60, 60, 60,
                                                                            60, 30, 60 });
    parms.set_coeff_modulus(coeff_modulus);
    parms.set_plain_modulus(params.q);

    prng_seed_type seed;
    for (auto &i : seed) {
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
    keygen.create_relin_keys(relin_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    BatchEncoder batch_encoder(context);

    // w.l.o.g, use the first member in the group to test, ideally, any one should be able to detect same pertinent messages
    fgomr::FixedGroupDetectionKey switchingKey = fgomr::generateDetectionKey(params, context, poly_modulus_degree, public_key, secret_key, groupSK[4]);
    Ciphertext packedSIC;

    vector<vector<PVWCiphertext>> SICPVW_multicore(numcores);
    vector<vector<vector<uint64_t>>> payload_multicore(numcores);
    vector<int> counter(numcores);

    GaloisKeys gal_keys;
    vector<int> stepsfirst = {1};
    // only one rot key is needed for full level
    keygen.create_galois_keys(stepsfirst, gal_keys);

    /////////////////////////////////////////////////////////////// Rot Key gen
    vector<int> steps = {0};
    for(int i = 1; i < int(poly_modulus_degree/2); i *= 2) {
	    steps.push_back(i);
    }

    cout << "Finishing generating detection keys\n";

    /////////////////////////////////////// Level specific keys
    vector<Modulus> coeff_modulus_next = coeff_modulus;
    coeff_modulus_next.erase(coeff_modulus_next.begin() + 4, coeff_modulus_next.end()-1);
    EncryptionParameters parms_next = parms;
    parms_next.set_coeff_modulus(coeff_modulus_next);
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
    keygen_next.create_galois_keys(steps_next, gal_keys_next);

    //////////////////////////////////////
    vector<Modulus> coeff_modulus_last = coeff_modulus;
    coeff_modulus_last.erase(coeff_modulus_last.begin() + 3, coeff_modulus_last.end()-1);
    EncryptionParameters parms_last = parms;
    parms_last.set_coeff_modulus(coeff_modulus_last);
    SEALContext context_last = SEALContext(parms_last, true, sec_level_type::none);

    SecretKey sk_last;
    sk_last.data().resize(coeff_modulus_last.size() * degree);
    sk_last.parms_id() = context_last.key_parms_id();
    util::set_poly(secret_key.data().data(), degree, coeff_modulus_last.size() - 1, sk_last.data().data());
    util::set_poly(
        secret_key.data().data() + degree * (coeff_modulus.size() - 1), degree, 1,
        sk_last.data().data() + degree * (coeff_modulus_last.size() - 1));
    vector<int> steps_last = {1,2,4,8,16};
    KeyGenerator keygen_last(context_last, sk_last);
    keygen_last.create_galois_keys(steps, gal_keys_last);
    //////////////////////////////////////
    PublicKey public_key_last;
    keygen_next.create_public_key(public_key_last);
    //////////////////////////////////////

    vector<vector<Ciphertext>> packedSICfromPhase1(numcores,vector<Ciphertext>(numOfTransactions/numcores/poly_modulus_degree)); // Assume numOfTransactions/numcores/poly_modulus_degree is integer, pad if needed

    NTL::SetNumThreads(numcores);
    SecretKey secret_key_blank;

    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    time_start = chrono::high_resolution_clock::now();

    MemoryPoolHandle my_pool = MemoryPoolHandle::New();
    auto old_prof = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool)));
    NTL_EXEC_RANGE(numcores, first, last);
    for (int i = first; i < last; i++) {
        counter[i] = numOfTransactions/numcores*i;

        size_t j = 0;
        while(j < numOfTransactions/numcores/poly_modulus_degree) {
            if (!i)
                cout << "Phase 1, Core " << i << ", Batch " << j << endl;
            loadClues(SICPVW_multicore[i], counter[i], counter[i]+poly_modulus_degree, params);
            packedSICfromPhase1[i][j] = serverOperations1obtainPackedSIC(SICPVW_multicore[i], switchingKey, relin_keys, gal_keys,
                                                            poly_modulus_degree, context, params, poly_modulus_degree);
            j++;
            counter[i] += poly_modulus_degree;
            SICPVW_multicore[i].clear();
        }
    }
    NTL_EXEC_RANGE_END;
    MemoryManager::SwitchProfile(std::move(old_prof));

    // step 4. detector operations
    vector<vector<Ciphertext>> lhs_multi_ctr(numcores);
    vector<Ciphertext> rhs_multi(numcores);
    vector<vector<vector<int>>> bipartite_map(numcores);

    for (auto &i : seed_glb) {
        i = random_uint64();
    }
    bipartiteGraphWeightsGeneration(bipartite_map_glb, weights_glb, numOfTransactions, OMRthreeM, repeatition_glb, seed_glb);

    int number_of_ct = ceil(repetition_glb * 3 * 512 / ((poly_modulus_degree_glb / 512 / 3 * 3 * 512) * 1.0));

    NTL_EXEC_RANGE(numcores, first, last);
    for (int i = first; i < last; i++) {
        MemoryPoolHandle my_pool = MemoryPoolHandle::New();
        auto old_prof = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool)));
        size_t j = 0;
        counter[i] = numOfTransactions/numcores*i;

        while (j < numOfTransactions/numcores/poly_modulus_degree) {
            if (!i)
                cout << "Phase 2-3, Core " << i << ", Batch " << j << endl;
            loadData(payload_multicore[i], counter[i], counter[i]+poly_modulus_degree);
            vector<Ciphertext> templhsctr;
            Ciphertext temprhs;
            serverOperations3therest(templhsctr, bipartite_map[i], temprhs, packedSICfromPhase1[i][j], payload_multicore[i],
                            relin_keys, gal_keys_next, public_key_last, poly_modulus_degree, context_next, context_last,
                            params, poly_modulus_degree, counter[i], number_of_ct);

            if (j == 0) {
                lhs_multi_ctr[i] = templhsctr;
                rhs_multi[i] = temprhs;
            } else {
                for (size_t q = 0; q < lhs_multi_ctr[i].size(); q++) {
                    evaluator.add_inplace(lhs_multi_ctr[i][q], templhsctr[q]);
                }
                evaluator.add_inplace(rhs_multi[i], temprhs);
            }
            j++;
            payload_multicore[i].clear();
        }
        MemoryManager::SwitchProfile(std::move(old_prof));
    }
    NTL_EXEC_RANGE_END;

    for (int i = 1; i < numcores; i++) {
        for (size_t q = 0; q < lhs_multi_ctr[i].size(); q++) {
            evaluator.add_inplace(lhs_multi_ctr[0][q], lhs_multi_ctr[i][q]);
        }
        evaluator.add_inplace(rhs_multi[0], rhs_multi[i]);
    }

    while (context.last_parms_id() != lhs_multi_ctr[0][0].parms_id()) {
        for (size_t q = 0; q < lhs_multi_ctr[0].size(); q++) {
            evaluator.mod_switch_to_next_inplace(lhs_multi_ctr[0][q]);
        }
        evaluator.mod_switch_to_next_inplace(rhs_multi[0]);
    }

    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "\nDetector running time: " << time_diff.count() << "us." << "\n";

    stringstream data_streamdg, data_streamdg2;
    auto digsize = rhs_multi[0].save(data_streamdg);
    for (size_t q = 0; q < lhs_multi_ctr[0].size(); q++) {
        digsize += lhs_multi_ctr[0][q].save(data_streamdg2);
    }
    cout << "Digest size: " << digsize << " bytes" << endl;

    // step 5. receiver decoding
    bipartiteGraphWeightsGeneration(bipartite_map_glb, weights_glb, numOfTransactions, OMRthreeM, repeatition_glb, seed_glb);
    time_start = chrono::high_resolution_clock::now();
    auto res = receiverDecodingOMR3(lhs_multi_ctr[0], bipartite_map[0], rhs_multi[0],
                        poly_modulus_degree, secret_key, context, numOfTransactions);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "\nRecipient running time: " << time_diff.count() << "us." << "\n";

    if (checkRes(expected, res))
        cout << "Result is correct!" << endl;
    else
        cout << "Overflow" << endl;
}