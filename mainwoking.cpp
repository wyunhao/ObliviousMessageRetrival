//#include "PVWToBFV.h"
#include "unitTests.h"
#include "LoadAndSaveUtils.h"

using namespace seal;

void genTestData(){
    createDatabase();
    //createSICforEachTransaction(450, 65537, 1.2, 1, 524288, 32768);
}

vector<vector<uint64_t>> preparinngTransactions(vector<PVWCiphertext>& SICPVW, vector<vector<uint64_t>>& payload, PVWsk& sk, int numOfTransactions, int pertinentfactor, const PVWParam& params){
    srand (time(NULL));
    //auto pk = PVWGeneratePublicKey(params, sk);

    vector<int> msgs(numOfTransactions);
    vector<vector<uint64_t>> ret;
    SICPVW.resize(numOfTransactions);
    vector<int> zeros(params.ell, 0);
    for(int i = 0; i < numOfTransactions; i++){
        if(rand()%pertinentfactor == 0){
            PVWEncSK(SICPVW[i], zeros, sk, params);
            msgs[i] = 1;
        }
        else
        {
            auto sk2 = PVWGenerateSecretKey(params);
            PVWEncSK(SICPVW[i], zeros, sk2, params);
            msgs[i] = 0;
        }
    }

    payload = loadData(numOfTransactions, 306);
    cout << "Supposed result: \n";
    for(int i = 0; i < numOfTransactions; i++){
        if(msgs[i]){
            cout << i << ": " << payload[i] << endl;
            ret.push_back(payload[i]);
        }
    }
    return ret;
}

Ciphertext serverOperations1Previous(SecretKey& sk, vector<PVWCiphertext>& SICPVW, vector<vector<Ciphertext>>& switchingKey, const RelinKeys& relin_keys,
                            const size_t& degree, const SEALContext& context, const PVWParam& params, const int numOfTransactions){

    Decryptor decryptor(context, sk);
    Evaluator evaluator(context);
    
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;

    time_start = chrono::high_resolution_clock::now();
    vector<Ciphertext> packedSIC;
    computeBplusASPVW(packedSIC, SICPVW, switchingKey, context, params);
    switchingKey.clear();
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << time_diff.count() << " " << "1\n";

    time_start = chrono::high_resolution_clock::now();
    int rangeToCheck = 32; // range check is from [-rangeToCheck, rangeToCheck-1]
    evalRangeCheckMemorySavingOptimizedPVW(packedSIC, rangeToCheck, relin_keys, degree, context, params);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << time_diff.count() << " " << "2\n";

    cout << decryptor.invariant_noise_budget(packedSIC[0]) << " bits left" << endl;
    for(int i = 0; i < 6; i++)
        evaluator.mod_switch_to_next_inplace(packedSIC[0]);
    // evaluator.mod_switch_to_next_inplace(packedSIC);
    cout << decryptor.invariant_noise_budget(packedSIC[0]) << " bits left" << endl;

    return packedSIC[0];
}

Ciphertext serverOperations1obtainPackedSIC(SecretKey& sk, vector<PVWCiphertext>& SICPVW, vector<vector<Ciphertext>>& switchingKey, const RelinKeys& relin_keys,
                            const size_t& degree, const SEALContext& context, const PVWParam& params, const int numOfTransactions){

    Decryptor decryptor(context, sk);
    Evaluator evaluator(context);
    
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    // cout << "1: " << SICPVW[0].parms_id();

    time_start = chrono::high_resolution_clock::now();
    vector<Ciphertext> packedSIC;
    computeBplusASPVW(packedSIC, SICPVW, switchingKey, context, params);
    switchingKey.clear();
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << time_diff.count() << " " << "1\n";
    cout << "2: " << packedSIC[0].parms_id() << endl;

    time_start = chrono::high_resolution_clock::now();
    int rangeToCheck = 850; // range check is from [-rangeToCheck, rangeToCheck-1]
    newRangeCheckPVW(packedSIC, rangeToCheck, relin_keys, degree, context, params);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << time_diff.count() << " " << "2\n";
    cout << "3: " << packedSIC[0].parms_id() << endl;

    cout << decryptor.invariant_noise_budget(packedSIC[0]) << " bits left" << endl;
    // for(int i = 0; i < 1; i++)
        // evaluator.mod_switch_to_next_inplace(packedSIC[0]);
    //evaluator.mod_switch_to_next_inplace(packedSIC);
    cout << decryptor.invariant_noise_budget(packedSIC[0]) << " bits left" << endl;
    cout << "3: " << packedSIC[0].parms_id() << endl;

    return packedSIC[0];
}

void serverOperations2therest(Ciphertext& lhs, vector<vector<int>>& bipartite_map, Ciphertext& rhs, SecretKey& sk, // sk just for test
                        Ciphertext& packedSIC, const vector<vector<uint64_t>>& payload, const RelinKeys& relin_keys, const GaloisKeys& gal_keys,
                        const size_t& degree, const SEALContext& context, const PVWParam& params, const int numOfTransactions, size_t counter = 0, const int payloadSize = 306){

    Decryptor decryptor(context, sk);
    Evaluator evaluator(context);
    NTL::SetNumThreads(8);

    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;

    // 5. generate bipartite graph. in real application, we return only the seed, but in demo, we directly give the graph
    time_start = chrono::high_resolution_clock::now();
    int repeatition = 5;
    int seed = 3;
    // bipartiteGraphGeneration(bipartite_map,numOfTransactions,100,repeatition,seed);
    vector<vector<int>> weights;
    bipartiteGraphWeightsGeneration(bipartite_map, weights,numOfTransactions,100,repeatition,seed);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << time_diff.count() << " " << "5\n";

    int step = 32;
    time_start = chrono::high_resolution_clock::now();
    // while(context.last_parms_id() != packedSIC.parms_id()){
        // evaluator.mod_switch_to_next_inplace(packedSIC);
    // }
    for(int i = 0; i < numOfTransactions; i += step){
        if (i % 256 == 0){
            cout << i <<" " << numOfTransactions << endl;
            chrono::high_resolution_clock::time_point time_start2, time_end2;
            chrono::microseconds time_diff2;
            // cout << i <<" " << numOfTransactions << endl;
            // 3 4 6 7. expand SIC; retrieve indices; retrieve payloads, shift the payload according to the graph; payload paking
            time_start2 = chrono::high_resolution_clock::now();
            vector<Ciphertext> expandedSIC;
            expandSIC(expandedSIC, packedSIC, gal_keys, int(degree), context, step, i);
            time_end2 = chrono::high_resolution_clock::now();
            time_diff2 = chrono::duration_cast<chrono::microseconds>(time_end2 - time_start2);
            cout << time_diff2.count() << " " << "3\n";
    
            time_start2 = chrono::high_resolution_clock::now();
            deterministicIndexRetrieval(lhs, expandedSIC, context, degree, i);
            time_end2 = chrono::high_resolution_clock::now();
            time_diff2 = chrono::duration_cast<chrono::microseconds>(time_end2 - time_start2);
            cout << time_diff2.count() << " " << "4\n";
    
            time_start2 = chrono::high_resolution_clock::now();
            vector<vector<Ciphertext>> payloadUnpacked;
            // payloadRetrievalOptimized(payloadUnpacked, payload, bipartite_map, expandedSIC, context, i);
            payloadRetrievalOptimizedwithWeights(payloadUnpacked, payload, bipartite_map, weights, expandedSIC, context, i);
            time_end2 = chrono::high_resolution_clock::now();
            time_diff2 = chrono::duration_cast<chrono::microseconds>(time_end2 - time_start2);
            cout << time_diff2.count() << " " << "6\n";
    
            time_start2 = chrono::high_resolution_clock::now();
            payloadPackingOptimized(rhs, payloadUnpacked, bipartite_map, degree, context, gal_keys, i);
            time_end2 = chrono::high_resolution_clock::now();
            time_diff2 = chrono::duration_cast<chrono::microseconds>(time_end2 - time_start2);
            cout << time_diff2.count() << " " << "7\n";
        } else {
            // cout << i <<" " << numOfTransactions << endl;
            // 3 4 6 7. expand SIC; retrieve indices; retrieve payloads, shift the payload according to the graph; payload paking
            // time_start = chrono::high_resolution_clock::now();
            vector<Ciphertext> expandedSIC;
            expandSIC(expandedSIC, packedSIC, gal_keys, int(degree), context, step, i);
            // time_end = chrono::high_resolution_clock::now();
            // time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
            // cout << time_diff.count() << " " << "3\n";

            // time_start = chrono::high_resolution_clock::now();
            deterministicIndexRetrieval(lhs, expandedSIC, context, degree, i);
            // time_end = chrono::high_resolution_clock::now();
            // time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
            // cout << time_diff.count() << " " << "4\n";

            // time_start = chrono::high_resolution_clock::now();
            vector<vector<Ciphertext>> payloadUnpacked;
            // payloadRetrievalOptimized(payloadUnpacked, payload, bipartite_map, expandedSIC, context, i);
            payloadRetrievalOptimizedwithWeights(payloadUnpacked, payload, bipartite_map, weights, expandedSIC, context, i);
            // time_end = chrono::high_resolution_clock::now();
            // time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
            // cout << time_diff.count() << " " << "6\n";

            // time_start = chrono::high_resolution_clock::now();
            payloadPackingOptimized(rhs, payloadUnpacked, bipartite_map, degree, context, gal_keys, i);
        }
        
    }
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

void serverOperations3therest(vector<vector<Ciphertext>>& lhs, vector<Ciphertext>& lhsCounter, vector<vector<int>>& bipartite_map, Ciphertext& rhs, SecretKey& sk, // sk just for test
                        Ciphertext& packedSIC, const vector<vector<uint64_t>>& payload, const RelinKeys& relin_keys, const GaloisKeys& gal_keys, const PublicKey& public_key,
                        const size_t& degree, const SEALContext& context, const PVWParam& params, const int numOfTransactions, size_t counter = 0, const int payloadSize = 306){

    Decryptor decryptor(context, sk);
    Evaluator evaluator(context);
    NTL::SetNumThreads(8);

    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;

    // 5. generate bipartite graph. in real application, we return only the seed, but in demo, we directly give the graph
    time_start = chrono::high_resolution_clock::now();
    int repeatition = 5;
    int seed = 3;
    // bipartiteGraphGeneration(bipartite_map,numOfTransactions,20,repeatition,seed);
    vector<vector<int>> weights;
    bipartiteGraphWeightsGeneration(bipartite_map, weights,numOfTransactions,20,repeatition,seed);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << time_diff.count() << " " << "5\n";

    time_start = chrono::high_resolution_clock::now();
    int step = 32;
    // size_t counter = 0;
    for(int i = 0; i < numOfTransactions; i += step){
        if (1){
            cout << i <<" " << numOfTransactions << endl;
            chrono::high_resolution_clock::time_point time_start2, time_end2;
            chrono::microseconds time_diff2;
            // cout << i <<" " << numOfTransactions << endl;
            // 3 4 6 7. expand SIC; retrieve indices; retrieve payloads, shift the payload according to the graph; payload paking
            time_start2 = chrono::high_resolution_clock::now();
            vector<Ciphertext> expandedSIC;
            expandSIC(expandedSIC, packedSIC, gal_keys, int(degree), context, step, i);
            time_end2 = chrono::high_resolution_clock::now();
            time_diff2 = chrono::duration_cast<chrono::microseconds>(time_end2 - time_start2);
            cout << time_diff2.count() << " " << "3\n";
    
            time_start2 = chrono::high_resolution_clock::now();
            vector<vector<Ciphertext>> payloadUnpacked;
            // payloadRetrievalOptimized(payloadUnpacked, payload, bipartite_map, expandedSIC, context, i);
            payloadRetrievalOptimizedwithWeights(payloadUnpacked, payload, bipartite_map, weights, expandedSIC, context, i);
            time_end2 = chrono::high_resolution_clock::now();
            time_diff2 = chrono::duration_cast<chrono::microseconds>(time_end2 - time_start2);
            cout << time_diff2.count() << " " << "6\n";
    
            time_start2 = chrono::high_resolution_clock::now();
            payloadPackingOptimized(rhs, payloadUnpacked, bipartite_map, degree, context, gal_keys, i);
            time_end2 = chrono::high_resolution_clock::now();
            time_diff2 = chrono::duration_cast<chrono::microseconds>(time_end2 - time_start2);
            cout << time_diff2.count() << " " << "7\n";

		time_start2 = chrono::high_resolution_clock::now();
            randomizedIndexRetrieval(lhs, lhsCounter, expandedSIC, context, public_key, counter, degree, 5);
            time_end2 = chrono::high_resolution_clock::now();
            time_diff2 = chrono::duration_cast<chrono::microseconds>(time_end2 - time_start2);
            cout << time_diff2.count() << " " << "4\n";
    

        } else {
            // cout << i <<" " << numOfTransactions << endl;
            // 3 4 6 7. expand SIC; retrieve indices; retrieve payloads, shift the payload according to the graph; payload paking
            // time_start = chrono::high_resolution_clock::now();
            vector<Ciphertext> expandedSIC;
            expandSIC(expandedSIC, packedSIC, gal_keys, int(degree), context, step, i);
            // time_end = chrono::high_resolution_clock::now();
            // time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
            // cout << time_diff.count() << " " << "3\n";

                // time_start = chrono::high_resolution_clock::now();
            vector<vector<Ciphertext>> payloadUnpacked;
            // payloadRetrievalOptimized(payloadUnpacked, payload, bipartite_map, expandedSIC, context, i);
            payloadRetrievalOptimizedwithWeights(payloadUnpacked, payload, bipartite_map, weights, expandedSIC, context, i);
            // time_end = chrono::high_resolution_clock::now();
            // time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
            // cout << time_diff.count() << " " << "6\n";

            // time_start = chrono::high_resolution_clock::now();
            payloadPackingOptimized(rhs, payloadUnpacked, bipartite_map, degree, context, gal_keys, i);

		// time_start = chrono::high_resolution_clock::now();
            randomizedIndexRetrieval(lhs, lhsCounter, expandedSIC, context, public_key, counter, degree, 5);
            // time_end = chrono::high_resolution_clock::now();
            // time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
            // cout << time_diff.count() << " " << "4\n";
        }
        
    }
	for(size_t i = 0; i < lhs.size(); i++){
            evaluator.transform_from_ntt_inplace(lhs[i][0]);
            evaluator.transform_from_ntt_inplace(lhs[i][1]);
            evaluator.transform_from_ntt_inplace(lhsCounter[i]);
    }
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << time_diff.count() << " " << "7\n";

    while(context.last_parms_id() != rhs.parms_id()){
        cout << '?' << endl;
        for(size_t i = 0; i < lhs.size(); i++){
            for(size_t j = 0; j < lhs[i].size(); j++)
                evaluator.mod_switch_to_next_inplace(lhs[i][j]);
            evaluator.mod_switch_to_next_inplace(lhsCounter[i]);
        }
        evaluator.mod_switch_to_next_inplace(rhs);
    }
    //for(int i = 0; i < 2; i++){
    //    evaluator.mod_switch_to_next_inplace(rhs);
    //    evaluator.mod_switch_to_next_inplace(lhs);
    //}

    stringstream data_stream, data_stream2;
    cout << rhs.save(data_stream) << " bytes" << endl;
    cout << lhs[0][0].save(data_stream2) << " * 15 ~ bytes" << endl;
}

vector<vector<long>> receiverDecoding(Ciphertext& lhsEnc, vector<vector<int>>& bipartite_map, Ciphertext& rhsEnc,
                        const size_t& degree, const SecretKey& secret_key, const SEALContext& context, const int numOfTransactions, int seed = 3,
                        const int payloadUpperBound = 306, const int payloadSize = 306){

    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    time_start = chrono::high_resolution_clock::now();

    bipartite_map.clear();
    int repeatition = 5;
    // bipartiteGraphGeneration(bipartite_map,numOfTransactions,100,repeatition,seed);
    vector<vector<int>> weights;
    bipartiteGraphWeightsGeneration(bipartite_map,weights,numOfTransactions,100,repeatition,seed);

    // 1. find pertinent indices
    map<int, int> pertinentIndices;
    decodeIndices(pertinentIndices, lhsEnc, numOfTransactions, degree, secret_key, context);
    for (map<int, int>::iterator it = pertinentIndices.begin(); it != pertinentIndices.end(); it++)
    {
        std::cout << it->first    // string (key)
                  << ':'
                  << it->second   // string's value 
                  << std::endl;
    }
    cout << "1\n";
	time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << time_diff.count() << " microseconds for client to decode the result." << "\n";
        time_start = chrono::high_resolution_clock::now();

    // 2. forming rhs
    vector<vector<int>> rhs;
    formRhs(rhs, rhsEnc, secret_key, degree, context, 100);
    cout << "2\n";

	time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << time_diff.count() << " microseconds for client to decode the result." << "\n";
        time_start = chrono::high_resolution_clock::now();

    // 3. forming lhs
    vector<vector<int>> lhs;
    // formLhs(lhs, pertinentIndices, bipartite_map, 0, 100);
    formLhsWeights(lhs, pertinentIndices, bipartite_map, weights, 0, 100);
    cout << "3\n";

	time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << time_diff.count() << " microseconds for client to decode the result." << "\n";
	time_start = chrono::high_resolution_clock::now();

    // 4. solving equation
    auto newrhs = equationSolving(lhs, rhs, payloadSize);
    cout << "4\n";

    for(size_t i = 0; i < newrhs.size(); i++)
        cout << newrhs[i] << endl;

    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << time_diff.count() << " microseconds for client to decode the result." << "\n";

    return newrhs;
}

vector<vector<long>> receiverDecodingOMR3(vector<vector<Ciphertext>>& lhsEnc, vector<Ciphertext>& lhsCounter, vector<vector<int>>& bipartite_map, Ciphertext& rhsEnc,
                        const size_t& degree, const SecretKey& secret_key, const SEALContext& context, const int numOfTransactions, int seed = 3,
                        const int payloadUpperBound = 306, const int payloadSize = 306){

    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;

    time_start = chrono::high_resolution_clock::now();
    bipartite_map.clear();
    int repeatition = 5;
    // bipartiteGraphGeneration(bipartite_map,numOfTransactions,20,repeatition,seed);
    vector<vector<int>> weights;
    bipartiteGraphWeightsGeneration(bipartite_map,weights,numOfTransactions,20,repeatition,seed);
    cout << "0\n";
	time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << time_diff.count() << " microseconds for client to generat the bipartite graph." << "\n";
    time_start = chrono::high_resolution_clock::now();

    time_start = chrono::high_resolution_clock::now();
    // 1. find pertinent indices
    map<int, int> pertinentIndices;
    decodeIndicesRandom(pertinentIndices, lhsEnc, lhsCounter, degree, secret_key, context);
    for (map<int, int>::iterator it = pertinentIndices.begin(); it != pertinentIndices.end(); it++)
    {
        std::cout << it->first    // string (key)
                  << ':'
                  << it->second   // string's value 
                  << std::endl;
    }
    cout << "1\n";
	time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << time_diff.count() << " microseconds for client to decode the result." << "\n";
        time_start = chrono::high_resolution_clock::now();

    // 2. forming rhs
    vector<vector<int>> rhs;
    formRhs(rhs, rhsEnc, secret_key, degree, context, 20);
    cout << "2\n";

	time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << time_diff.count() << " microseconds for client to decode the result." << "\n";
        time_start = chrono::high_resolution_clock::now();

    // 3. forming lhs
    vector<vector<int>> lhs;
    // formLhs(lhs, pertinentIndices, bipartite_map, 0, 20);
    formLhsWeights(lhs, pertinentIndices, bipartite_map, weights, 0, 20);
    cout << "3\n";

	time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << time_diff.count() << " microseconds for client to decode the result." << "\n";
	time_start = chrono::high_resolution_clock::now();

    // 4. solving equation
    auto newrhs = equationSolving(lhs, rhs, payloadSize);
    cout << "4\n";

    for(size_t i = 0; i < newrhs.size(); i++)
        cout << newrhs[i] << endl;

    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << time_diff.count() << " microseconds for client to decode the result." << "\n";

    return newrhs;
}


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

void compressedDetectKeySize(){
    // step 1. generate PVW sk TODO: change to PK
    // receiver side
    auto params = regevParam(10, 65537, 1.2, 8100); 
    auto sk = regevGenerateSecretKey(params);
    cout << "Finishing generating sk for PVW cts\n";

    // step 3. generate detection key
    // receiver side
    //chrono::high_resolution_clock::time_point time_start, time_end;
    //chrono::microseconds time_diff;
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 32768;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 30, \
                                                                            25, 21, 31, 
                                                                            32, 31, 31, 31, 31, 31, 31, 31,
                                                                            31, 31, 32, 31, 31, 31, 31, 31, 31, 31, 31, 
                                                                            21, 28,
                                                                            20, 32 }));
    parms.set_plain_modulus(65537);


	prng_seed_type seed;
    for (auto &i : seed)
    {
        i = random_uint64();
    }
    auto rng = make_shared<Blake2xbPRNGFactory>(Blake2xbPRNGFactory(seed));
    parms.set_random_generator(rng);

    SEALContext context(parms, true, sec_level_type::none);
    print_parameters(context); //auto qualifiers = context.first_context_data()->qualifiers();
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    // keygen.create_relin_keys(relin_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    BatchEncoder batch_encoder(context);
    GaloisKeys gal_keys;

    vector<int> steps = {0};
    for(int i = 1; i < 32768/2; i *= 8){
	//steps.push_back(i);
        steps.push_back(32768/2 - i);
    }
    for(size_t i = 0; i < steps.size(); i++)
        cout << steps[i] << " ";
    cout << endl;

    seal::Serializable<PublicKey> pk = keygen.create_public_key();
	seal::Serializable<RelinKeys> rlk = keygen.create_relin_keys();
	stringstream streamPK, streamRLK, streamRTK;
    cout << "pk size: " << pk.save(streamPK) << endl;;
	cout << "rlk size: " << rlk.save(streamRLK) << endl;
	cout << "rot key size: " << keygen.create_galois_keys(steps).save(streamRTK) << endl;

    public_key.load(context, streamPK);
    relin_keys.load(context, streamRLK);
    gal_keys.load(context, streamRTK); //size_t slot_count = batch_encoder.slot_count();
	seal::Serializable<Ciphertext>  switchingKeypacked = genPackedSwitchingKey(context, poly_modulus_degree, public_key, secret_key, sk, params);
	stringstream data_stream;
    cout << "LWE sk (encrypted under BFV) size: " << switchingKeypacked.save(data_stream) << " bytes" << endl;
}

void OMR2(){

    int numOfTransactions = 256;
    createDatabase(numOfTransactions, 306); // one time
    cout << "Finishing createDatabase\n";

    // step 1. generate PVW sk TODO: change to PK
    // receiver side
    auto params = PVWParam(100, 65537, 1.2, 8100, 4); 
    auto sk = PVWGenerateSecretKey(params);
    cout << "Finishing generating sk for PVW cts\n";

    // step 2. prepare transactions
    // general
    vector<PVWCiphertext> SICPVW;
    vector<vector<uint64_t>> payload;
    auto expected = preparinngTransactions(SICPVW, payload, sk, numOfTransactions, 20, params);
    cout << expected.size() << " pertinent msg: Finishing preparing transactions\n";



    // step 3. generate detection key
    // receiver side
    //chrono::high_resolution_clock::time_point time_start, time_end;
    //chrono::microseconds time_diff;
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 32768;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 26, \
                                                                            21, 25, 31, 32, 31, 31, 31, 31, 31, 31, 31, \
                                                                            31, 31, 32, 31, 31, 31, 31, 31, 31, 31, 31,\
                                                                            21, 20, 32 }));
    parms.set_plain_modulus(65537);

	prng_seed_type seed;
    for (auto &i : seed)
    {
        i = random_uint64();
    }
    auto rng = make_shared<Blake2xbPRNGFactory>(Blake2xbPRNGFactory(seed));
    parms.set_random_generator(rng);

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

    // Context data
    auto context_data = context.first_context_data();
    while (context_data)
    {
        cout << " Level (chain index): " << context_data->chain_index();
        if (context_data->parms_id() == context.first_parms_id())
        {
            cout << " ...... first_context_data()" << endl;
        }
        else if (context_data->parms_id() == context.last_parms_id())
        {
            cout << " ...... last_context_data()" << endl;
        }
        else
        {
            cout << endl;
        }
        cout << "      parms_id: " << context_data->parms_id() << endl;
        cout << "      coeff_modulus primes: ";
        cout << hex;
        for (const auto &prime : context_data->parms().coeff_modulus())
        {
            cout << prime.value() << " ";
        }
        cout << dec << endl;
        cout << "\\" << endl;
        cout << " \\-->";

        /*
        Step forward in the chain.
        */
        context_data = context_data->next_context_data();
    }
    cout << " End of chain reached" << endl << endl;
    // end context data

    vector<vector<Ciphertext>> switchingKey;
    genSwitchingKeyPVW(switchingKey, context, poly_modulus_degree, public_key, sk, params);
    cout << 1 << endl;

    // vector<Ciphertext> vec;
    // vec.resize(500);
    // { // This bracket creates a scope.
    //     MemoryPoolHandle my_pool = MemoryPoolHandle::New();
    //     auto pg = seal::MMProfGuard(std::make_unique<MMProfFixed>(std::move(my_pool)));
    //     for (int i = 0; i < 500; i++) {
    //         encryptor.encrypt_zero(vec[i]);
    //     }
    //     for(int i = 0; i < 500;  i++){
    //         vec[i].release();
    //     }
    // } // This end bracket finishes the scope and destructs the new memory manager as it goes out of scope
    // vec.clear();

    // vector<vector<Ciphertext>> tst;
    // {
    //     genSwitchingKeyPVW(tst, context, poly_modulus_degree, public_key, sk, params);
    //     // cout << 2 << endl;
    //     for(size_t i = 0; i < tst.size(); i++){
    //         for(size_t j = 0; j < tst[i].size(); j++){
    //             tst[i][j].release();
    //         }
    //     }
    // }
    // tst.clear();

    cout << 3 << endl;

    auto packedSIC = serverOperations1obtainPackedSIC(secret_key, SICPVW, switchingKey, relin_keys, poly_modulus_degree, context, params, numOfTransactions);

    GaloisKeys gal_keys;
    vector<int> steps = {0};
    for(int i = 1; i < int(poly_modulus_degree/2); i *= 2){
	    steps.push_back(i);
    }
    keygen.create_galois_keys(steps, gal_keys);

    cout << "Finishing generating detection keys\n";

    // step 4. detector operations
    Ciphertext lhs, rhs;
    //evaluator.encrypt_zero(rhs);
    vector<vector<int>> bipartite_map;
    size_t counter = 0;
    serverOperations2therest(lhs, bipartite_map, rhs, secret_key,
                        packedSIC, payload, relin_keys, gal_keys,
                        poly_modulus_degree, context, params, numOfTransactions, counter);

    cout << decryptor.invariant_noise_budget(lhs) << " bits left" << endl;
    cout << decryptor.invariant_noise_budget(rhs) << " bits left" << endl;

    // step 5. receiver decoding
    auto res = receiverDecoding(lhs, bipartite_map, rhs,
                        poly_modulus_degree, secret_key, context, numOfTransactions);

    if(checkRes(expected, res))
        cout << "Result is correct!" << endl;
    else
        cout << "Overflow" << endl;
}

void OMR3(){

    int numOfTransactions = 128;
    createDatabase(numOfTransactions, 306); // one time
    cout << "Finishing createDatabase\n";

    // step 1. generate PVW sk TODO: change to PK
    // receiver side
    auto params = PVWParam(100, 65537, 1.2, 8100, 4); 
    auto sk = PVWGenerateSecretKey(params);
    cout << "Finishing generating sk for PVW cts\n";

    // step 2. prepare transactions
    // general
    vector<PVWCiphertext> SICPVW;
    vector<vector<uint64_t>> payload;
    auto expected = preparinngTransactions(SICPVW, payload, sk, numOfTransactions, 20, params);
    cout << expected.size() <<  ": Finishing preparing transactions\n";



    // step 3. generate detection key
    // receiver side
    //chrono::high_resolution_clock::time_point time_start, time_end;
    //chrono::microseconds time_diff;
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 32768;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 26, \
                                                                            21, 25, 31, 32, 31, 31, 31, 31, 31, 31, 31, \
                                                                            31, 31, 32, 31, 31, 31, 31, 31, 31, 31, 31,\
                                                                            21, 20, 32 }));
    parms.set_plain_modulus(65537);

	prng_seed_type seed;
    for (auto &i : seed)
    {
        i = random_uint64();
    }
    auto rng = make_shared<Blake2xbPRNGFactory>(Blake2xbPRNGFactory(seed));
    parms.set_random_generator(rng);

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

    vector<vector<Ciphertext>> switchingKey;
    genSwitchingKeyPVW(switchingKey, context, poly_modulus_degree, public_key, sk, params);

    auto packedSIC = serverOperations1obtainPackedSIC(secret_key, SICPVW, switchingKey, relin_keys, poly_modulus_degree, context, params, numOfTransactions);

    GaloisKeys gal_keys;
    vector<int> steps = {0};
    for(int i = 1; i < int(poly_modulus_degree/2); i *= 2){
	    steps.push_back(i);
    }
    keygen.create_galois_keys(steps, gal_keys);

    cout << "Finishing generating detection keys\n";

    // step 4. detector operations

    Ciphertext rhs;
    vector<vector<Ciphertext>> lhs;
    vector<Ciphertext> lhsctr;
    //evaluator.encrypt_zero(rhs);
    vector<vector<int>> bipartite_map;
    size_t counter = 0;
    serverOperations3therest(lhs, lhsctr, bipartite_map, rhs, secret_key,
                        packedSIC, payload, relin_keys, gal_keys, public_key,
                        poly_modulus_degree, context, params, numOfTransactions, counter);

    cout << decryptor.invariant_noise_budget(lhs[0][0]) << " bits left" << endl;
    cout << decryptor.invariant_noise_budget(rhs) << " bits left" << endl;

    // step 5. receiver decoding
    auto res = receiverDecodingOMR3(lhs, lhsctr, bipartite_map, rhs,
                        poly_modulus_degree, secret_key, context, numOfTransactions);
	cout << res.size() << endl;
    if(checkRes(expected, res))
        cout << "Result is correct!" << endl;
    else
        cout << "Overflow" << endl;
}

int main(){
    // degreeUpToTest();

    // 1. To check compressed detection size
    // compressedDetectKeySize();

    // 3. To run OMR3
    //OMR3();

    // 2. To run OMR2
    OMR2();

    
}
