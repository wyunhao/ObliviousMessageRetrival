#include "unitTests.h"
#include "LoadAndSaveUtils.h"

// void OMR2multi(){

//     int numOfTransactions = 256*4;
//     createDatabase(numOfTransactions, 306); // one time
//     cout << "Finishing createDatabase\n";

//     // step 1. generate PVW sk TODO: change to PK
//     // receiver side
//     auto params = PVWParam(100, 65537, 1.2, 8100, 4); 
//     auto sk = PVWGenerateSecretKey(params);
//     cout << "Finishing generating sk for PVW cts\n";

//     // step 2. prepare transactions
//     // general
//     vector<PVWCiphertext> SICPVW;
//     vector<vector<uint64_t>> payload;
//     auto expected = preparinngTransactions(SICPVW, payload, sk, numOfTransactions, 20, params, true);
//     cout << expected.size() << " pertinent msg: Finishing preparing transactions\n";



//     // step 3. generate detection key
//     // receiver side
//     //chrono::high_resolution_clock::time_point time_start, time_end;
//     //chrono::microseconds time_diff;
//     EncryptionParameters parms(scheme_type::bfv);
//     size_t poly_modulus_degree = 8192;
//     parms.set_poly_modulus_degree(poly_modulus_degree);
//     parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 26, \
//                                                                             21, 22,22, 31, 32, 31, 31, 31, 31, 31, 31, 31, \
//                                                                             31, 31, 32, 31, 31, 31, 31, 31, 31, 31, 31,\
//                                                                             21, 20, 32 }));
//     parms.set_plain_modulus(65537);

// 	prng_seed_type seed;
//     for (auto &i : seed)
//     {
//         i = random_uint64();
//     }
//     auto rng = make_shared<Blake2xbPRNGFactory>(Blake2xbPRNGFactory(seed));
//     parms.set_random_generator(rng);

//     SEALContext context(parms, true, sec_level_type::none);
//     print_parameters(context); //auto qualifiers = context.first_context_data()->qualifiers();
//     KeyGenerator keygen(context);
//     SecretKey secret_key = keygen.secret_key();
//     PublicKey public_key;
//     keygen.create_public_key(public_key);
//     RelinKeys relin_keys;
//     keygen.create_relin_keys(relin_keys);
//     Encryptor encryptor(context, public_key);
//     Evaluator evaluator(context);
//     Decryptor decryptor(context, secret_key);
//     BatchEncoder batch_encoder(context);

//     vector<vector<Ciphertext>> switchingKey;
//     Ciphertext packedSIC;
//     // {
//         // MemoryPoolHandle my_pool = MemoryPoolHandle::New();
//         // auto old_prof = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool)));
//     genSwitchingKeyPVW(switchingKey, context, poly_modulus_degree, public_key, sk, params);
    
//     int numcores = 4;
//     vector<vector<PVWCiphertext>> SICPVW_multicore(numcores);
//     vector<vector<vector<uint64_t>>> payload_multicore(numcores);
//     for(int i = 0; i < numcores; i++){
//         SICPVW_multicore[i] = vector<PVWCiphertext>(SICPVW.begin()+i*numOfTransactions/numcores, SICPVW.begin()+(i+1)*numOfTransactions/numcores);
//         payload_multicore[i] = vector<vector<uint64_t>>(payload_multicore.begin()+i*numOfTransactions/numcores, payload_multicore.begin()+(i+1)*numOfTransactions/numcores);
//     }

//     vector<Ciphertext> temps(numcores);

//     NTL::SetNumThreads(numcores);
//     NTL_EXEC_RANGE(numcores, first, last);
//     for(int i = first; i < last; i++){
//         temps[i] = serverOperations1obtainPackedSIC(secret_key, SICPVW_multicore[i], switchingKey, relin_keys, 
//                                                         poly_modulus_degree, context, params, numOfTransactions/numcores);
//     }
//     NTL_EXEC_RANGE_END;
    
//     // MemoryManager::SwitchProfile(std::move(old_prof));
    
//     packedSIC = temp[0];
//     // }

//     GaloisKeys gal_keys;
//     vector<int> steps = {0};
//     for(int i = 1; i < int(poly_modulus_degree/2); i *= 2){
// 	    steps.push_back(i);
//     }
//     keygen.create_galois_keys(steps, gal_keys);

//     cout << "Finishing generating detection keys\n";

//     // step 4. detector operations
//     vector<Ciphertext> lhs_multi(numcores), rhs_multi(numcores);
//     vector<vector<vector<int>>> bipartite_map(numcores);
//     vector<size_t> counter(numcores);

//     NTL_EXEC_RANGE(numcores, first, last);
//     for(int i = first; i < last; i++){
//         //evaluator.encrypt_zero(rhs);
//         serverOperations2therest(lhs_multi[i], bipartite_map[i], rhs_multi[i] = rhs, secret_key,
//                             temps[i], payload_multicore[i], relin_keys, gal_keys,
//                             poly_modulus_degree, context, params, numOfTransactions/numcores, counter[i]);
//     }
//     NTL_EXEC_RANGE_END;

//     // step 5. receiver decoding
//     auto res = receiverDecoding(lhs_multi[0], bipartite_map[0], rhs_multi[0],
//                         poly_modulus_degree, secret_key, context, numOfTransactions/numcores);

//     if(checkRes(expected, res))
//         cout << "Result is correct!" << endl;
//     else
//         cout << "Overflow" << endl;
    
//     for(size_t i = 0; i < res.size(); i++){

//     }
// }