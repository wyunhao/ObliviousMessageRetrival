//#include "regevToBFV.h"
#include "unitTests.h"
#include "LoadAndSaveUtils.h"

using namespace seal;

void genTestData(){
    createDatabase();
    //createSICforEachTransaction(450, 65537, 1.2, 1, 524288, 32768);
}

void preparinngTransactions(vector<vector<regevCiphertext>>& SICregev, vector<vector<uint64_t>>& payload, regevSK& sk, int numOfTransactions, const regevParam& params){
    srand (time(NULL));
    //auto pk = regevGeneratePublicKey(params, sk);

    SICregev.resize(4);
    SICregev[0].resize(numOfTransactions);
    SICregev[1].resize(numOfTransactions);
    SICregev[2].resize(numOfTransactions);
    SICregev[3].resize(numOfTransactions);
    vector<int> msgs(numOfTransactions);
    for(int i = 0; i < numOfTransactions; i++){
        if(rand()%10 == 0){
            regevEncSK(SICregev[0][i], 0, sk, params);
            regevEncSK(SICregev[1][i], 0, sk, params);
            regevEncSK(SICregev[2][i], 0, sk, params);
            regevEncSK(SICregev[3][i], 0, sk, params);
            msgs[i] = 1;
        }
        else
        {
            auto sk2 = regevGenerateSecretKey(params);
            regevEncSK(SICregev[0][i], 0, sk2, params);
            regevEncSK(SICregev[1][i], 0, sk2, params);
            regevEncSK(SICregev[2][i], 0, sk2, params);
            regevEncSK(SICregev[3][i], 0, sk2, params);
            msgs[i] = 0;
        }
    }

    //for(int i = 0; i < numOfTransactions; i++){
    //    cout << msgs[i] << " ";
    //}
    //cout << endl;
//
    payload = loadData(numOfTransactions, 290);
    //cout << "Supposed result: \n";
    //for(int i = 0; i < numOfTransactions; i++){
    //    if(msgs[i])
    //        cout << i << ": " << payload[i] << endl;
    //}
}

void serverOperations(Ciphertext& lhs, vector<vector<int>>& bipartite_map, Ciphertext& rhs, SecretKey& sk, // sk just for test
                        const vector<regevCiphertext>& SICregev, const vector<vector<uint64_t>>& payload, vector<Ciphertext>& switchingKey, const RelinKeys& relin_keys, const GaloisKeys& gal_keys,
                        const size_t& degree, const SEALContext& context, const regevParam& params, const int numOfTransactions, size_t counter = 0, const int payloadSize = 512){

    Decryptor decryptor(context, sk);
    Evaluator evaluator(context);
    NTL::SetNumThreads(8);

    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;

    // 1. compute b - as
    time_start = chrono::high_resolution_clock::now();
    Ciphertext packedSIC;
    computeBplusASMulti(packedSIC, SICregev, switchingKey, context, params);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    switchingKey.clear();
    cout << time_diff.count() << " " << "1\n";

    // 2. range check
    time_start = chrono::high_resolution_clock::now();
    int rangeToCheck = 64; // range check is from [-rangeToCheck, rangeToCheck-1]
    evalRangeCheckMemorySavingMulti(packedSIC, rangeToCheck, relin_keys, degree, context, params);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << time_diff.count() << " " << "2\n";
    cout << decryptor.invariant_noise_budget(packedSIC) << " bits left" << endl;
    for(int i = 0; i < 6; i++)
        evaluator.mod_switch_to_next_inplace(packedSIC);
    //evaluator.mod_switch_to_next_inplace(packedSIC);
    cout << decryptor.invariant_noise_budget(packedSIC) << " bits left" << endl;

    // 3. expand SIC
    time_start = chrono::high_resolution_clock::now();
    vector<Ciphertext> expandedSIC;
    expandSICMulti(expandedSIC, packedSIC, gal_keys, int(degree), context, numOfTransactions);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << time_diff.count() << " " << "3\n";

    // 4. retrieve indices
    time_start = chrono::high_resolution_clock::now();
    deterministicIndexRetrievalMulti(lhs, expandedSIC, context, degree, counter);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << time_diff.count() << " " << "4\n";

    // 5. retrieve payloads
    time_start = chrono::high_resolution_clock::now();
    vector<Ciphertext> payloadUnpacked(numOfTransactions);
    payloadRetrievalMulti(payloadUnpacked, payload, expandedSIC, context);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << time_diff.count() << " " << "5\n";

    // 6. generate bipartite graph. in real application, we return only the seed, but in demo, we directly give the graph
    time_start = chrono::high_resolution_clock::now();
    int repeatition = 5;
    int seed = 3;
    bipartiteGraphGeneration(bipartite_map,numOfTransactions,64,repeatition,seed);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << time_diff.count() << " " << "6\n";

    // 7. payload paking
    time_start = chrono::high_resolution_clock::now();
    payloadPackingMulti(rhs, payloadUnpacked, bipartite_map, degree, context, gal_keys);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << time_diff.count() << " " << "7\n";

    while(context.last_parms_id() != rhs.parms_id()){
        evaluator.mod_switch_to_next_inplace(rhs);
        evaluator.mod_switch_to_next_inplace(lhs);
    }
    //for(int i = 0; i < 2; i++){
    //    evaluator.mod_switch_to_next_inplace(rhs);
    //    evaluator.mod_switch_to_next_inplace(lhs);
    //}

    stringstream data_stream, data_stream2;
    cout << rhs.save(data_stream) << " bytes" << endl;
    cout << lhs.save(data_stream2) << " bytes" << endl;
}

void receiverDecoding(Ciphertext& lhsEnc, vector<vector<int>>& bipartite_map, Ciphertext& rhsEnc,
                        const size_t& degree, const SecretKey& secret_key, const SEALContext& context, const int numOfTransactions,
                        const int payloadUpperBound = 512, const int payloadSize = 290){

    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    time_start = chrono::high_resolution_clock::now();

    // 1. find pertinent indices
    map<int, int> pertinentIndices;
    decodeIndices(pertinentIndices, lhsEnc, numOfTransactions, degree, secret_key, context);
    //for (map<int, int>::iterator it = pertinentIndices.begin(); it != pertinentIndices.end(); it++)
    //{
    //    std::cout << it->first    // string (key)
    //              << ':'
    //              << it->second   // string's value 
    //              << std::endl;
    //}
    cout << "1\n";

    // 2. forming rhs
    vector<vector<int>> rhs;
    formRhs(rhs, rhsEnc, secret_key, degree, context);
    cout << "2\n";

    // 3. forming lhs
    vector<vector<int>> lhs;
    formLhs(lhs, pertinentIndices, bipartite_map);
    cout << "3\n";

    // 4. solving equation
    auto newrhs = equationSolving(lhs, rhs, payloadSize);
    cout << "4\n";

    //for(size_t i = 0; i < newrhs.size(); i++)
    //    cout << newrhs[i] << endl;

    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << time_diff.count() << " " << "\n";
}

int main(){
    int numOfTransactions = 100;
    createDatabase(numOfTransactions, 290); // one time
    cout << "Finishing createDatabase\n";

    // step 1. generate regev sk TODO: change to PK
    // receiver side
    auto params = regevParam(200, 65537, 1.2, 8100); 
    auto sk = regevGenerateSecretKey(params);
    cout << "Finishing generating sk for regev cts\n";

    // step 2. prepare transactions
    // general
    vector<vector<regevCiphertext>> SICregev;
    vector<vector<uint64_t>> payload;
    preparinngTransactions(SICregev, payload, sk, numOfTransactions, params);
    cout << "Finishing preparing transactions\n";

    // step 3. generate detection key
    // receiver side
    //chrono::high_resolution_clock::time_point time_start, time_end;
    //chrono::microseconds time_diff;
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 32768;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 30, \
                                                                            30, 30, 30, 30, 30, 30, 30, 30, 30, 30, \
                                                                            30, 30, 30, 30, 30, 30, 30, 30, 30, 30,\
                                                                            30, 30, 30, 30, 30, 30, 30, 30, 30,\
                                                                             30, 30, 35 }));
    parms.set_plain_modulus(65537);
    SEALContext context(parms, true, sec_level_type::none);
    print_parameters(context); //auto qualifiers = context.first_context_data()->qualifiers();
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
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys); //size_t slot_count = batch_encoder.slot_count();
    vector<Ciphertext> switchingKey;
    genSwitchingKey(switchingKey, context, poly_modulus_degree, public_key, sk, params);
    cout << "Finishing generating detection keys\n";

    // step 4. detector operations
    Ciphertext lhs, rhs;
    //evaluator.encrypt_zero(rhs);
    vector<vector<int>> bipartite_map;
    size_t counter = 0;
    serverOperations(lhs, bipartite_map, rhs, secret_key,
                        SICregev[0], payload, switchingKey, relin_keys, gal_keys,
                        poly_modulus_degree, context, params, numOfTransactions, counter);

    cout << decryptor.invariant_noise_budget(lhs) << " bits left" << endl;
    cout << decryptor.invariant_noise_budget(rhs) << " bits left" << endl;

    // step 5. receiver decoding
    receiverDecoding(lhs, bipartite_map, rhs,
                        poly_modulus_degree, secret_key, context, numOfTransactions);

//testMomerySavingBPlusA10();
    //regevTest();
    //bfvRangeCheckTest();
    //bfvFromRegevTest();
}