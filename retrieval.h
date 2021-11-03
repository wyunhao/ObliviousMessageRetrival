#pragma once

#include "regevToBFVSeal.h"
#include <algorithm>

// one transaction taking one bit
// this takes less than 10^-3 sec per transac, single threaded
void deterministicIndexRetrieval(Ciphertext& indexIndicator, const vector<Ciphertext>& SIC, const SEALContext& context, 
                                    const size_t& degree, const size_t& start
                                    , bool isMulti = false){ // counter is used to optimize memory use, not needed for now
    BatchEncoder batch_encoder(context);
    Evaluator evaluator(context);
    vector<uint64_t> pod_matrix(degree, 0ULL); // TODOmulti: move inside to the loop for multi-threading
    if(start + SIC.size() >= 16*degree){
        cerr << "counter + SIC.size should be less, please check" << endl;
        return;
    }
    // if(SIC.size() > 16*306){ // This is because we only recover 306 slots for expandSIC, for efficiency.
    //     cout << "Take at most 4896 elements at a time." << endl;
    //     return;
    // }
    // auto saver = counter;
    //if(!isMulti){ // if not multi, counter needs to start from 0 and then add back
    //    counter = 0;
    //}

    // cout << "counter: " << start << endl;

    for(size_t i = 0; i < SIC.size(); i++){
        size_t idx = (i+start)/16; // modulus is 65537, so we can support at most 16 bits per slot
        size_t shift = (i+start) % 16;
        pod_matrix[idx] = (1<<shift);
        Plaintext plain_matrix;
        batch_encoder.encode(pod_matrix, plain_matrix);
        evaluator.transform_to_ntt_inplace(plain_matrix, SIC[i].parms_id());
        // cout << i << " ~~~ " << plain_matrix.is_ntt_form() << " ~~~ " << SIC[i].is_ntt_form() << endl;
        if(i == 0 && (start%degree) == 0){
            evaluator.multiply_plain(SIC[i], plain_matrix, indexIndicator);
        }
        else{
            Ciphertext temp;
            evaluator.multiply_plain(SIC[i], plain_matrix, temp);
            evaluator.add_inplace(indexIndicator, temp);
        }
        pod_matrix[idx] = 0ULL;
    }

    //if(!isMulti){ // if not multi, counter needs to start from 0 and then add back
    //    counter += saver;
    //}
}

void randomizedIndexRetrieval(vector<vector<Ciphertext>>& indexIndicator, vector<Ciphertext>& indexCounters, vector<Ciphertext>& SIC, const SEALContext& context, 
                                        const PublicKey& BFVpk, size_t& counter, const size_t& degree, size_t C){ // counter is used to optimize memory use, not needed for now
    BatchEncoder batch_encoder(context);
    Evaluator evaluator(context);
    Encryptor encryptor(context, BFVpk);
    vector<uint64_t> pod_matrix(degree, 0ULL); // TODOmulti: move inside to the loop for multi-threading
    srand(time(NULL));

    // for(size_t i = 0; i < SIC.size(); i++){
    //     evaluator.mod_switch_to_next_inplace(SIC[i]);
    // }

    if(counter == 0){ // first msg
        indexIndicator.resize(C);
        indexCounters.resize(C);
        for(size_t i = 0; i < C; i++){
            indexIndicator[i].resize(2); // 2 cts allow 65537^2 total messages, which is in general enough so we hard code this.
            encryptor.encrypt_zero(indexIndicator[i][0]);
            encryptor.encrypt_zero(indexIndicator[i][1]);
            encryptor.encrypt_zero(indexCounters[i]);
            evaluator.mod_switch_to_inplace(indexIndicator[i][0], SIC[0].parms_id());
            evaluator.mod_switch_to_inplace(indexIndicator[i][1], SIC[0].parms_id());
            evaluator.mod_switch_to_inplace(indexCounters[i], SIC[0].parms_id());
            evaluator.transform_to_ntt_inplace(indexIndicator[i][0]);
            evaluator.transform_to_ntt_inplace(indexIndicator[i][1]);
            evaluator.transform_to_ntt_inplace(indexCounters[i]);
        }
    }

    for(size_t i = 0; i < SIC.size(); i++){
        // cout << "hey!" << endl;
        evaluator.transform_to_ntt_inplace(SIC[i]);
        for(size_t j = 0; j < C; j++){
            // cout <<"here iteration: " << i << " " << j << ": ";
            size_t index = rand()%degree;
            // cout << index << " ";

            vector<uint64_t> pod_matrix(degree, 0ULL);
            Ciphertext temp;

            pod_matrix[index] = counter/65537;
            if(pod_matrix[index] == 0){
                // then nothing to do
            } else {
                Plaintext plain_matrix;
                batch_encoder.encode(pod_matrix, plain_matrix);
                evaluator.transform_to_ntt_inplace(plain_matrix, SIC[i].parms_id());
                evaluator.multiply_plain(SIC[i], plain_matrix, temp);
                // evaluator.transform_from_ntt_inplace(temp);
                evaluator.add_inplace(indexIndicator[j][0], temp);
            }

            // cout << counter << " ";

            pod_matrix[index] = counter%65537;
            if(pod_matrix[index] == 0){
                // then nothing to do
            } else {
                Plaintext plain_matrix;
                batch_encoder.encode(pod_matrix, plain_matrix);
                evaluator.transform_to_ntt_inplace(plain_matrix, SIC[i].parms_id());
                evaluator.multiply_plain(SIC[i], plain_matrix, temp);
                // evaluator.transform_from_ntt_inplace(temp);
                evaluator.add_inplace(indexIndicator[j][1], temp);
            }

            // cout << i<< endl;

            pod_matrix[index] = 1;
            if(pod_matrix[index] == 0){
                // then nothing to do
            } else {
                Plaintext plain_matrix;
                batch_encoder.encode(pod_matrix, plain_matrix);
                evaluator.transform_to_ntt_inplace(plain_matrix, SIC[i].parms_id());
                evaluator.multiply_plain(SIC[i], plain_matrix, temp);
                // evaluator.transform_from_ntt_inplace(temp);
                evaluator.add_inplace(indexCounters[j], temp);
            }
            // evaluator.transform_from_ntt_inplace(SIC[i]);
        }
        counter += 1;
    }
    return;
}

void payloadRetrieval(vector<Ciphertext>& results, const vector<vector<uint64_t>>& payloads, const vector<Ciphertext>& SIC, const SEALContext& context){ // TODOmulti: can be multithreaded extremely easily
    Evaluator evaluator(context);
    BatchEncoder batch_encoder(context);
    results.resize(SIC.size());

    for(size_t i = 0; i < SIC.size(); i++){
        Plaintext plain_matrix;
        batch_encoder.encode(payloads[i], plain_matrix);

        evaluator.multiply_plain(SIC[i], plain_matrix, results[i]);
    }
}

void bipartiteGraphGeneration(vector<vector<int>>& bipartite_map, const int& num_of_transactions, const int& num_of_buckets, const int& repetition, const int& seed){
    srand(seed);
    bipartite_map.resize(num_of_transactions);
    for(int i = 0; i < num_of_transactions; i++)
    {
        bipartite_map[i].resize(repetition, -1);
        for(int j = 0; j < repetition; j++){
            int temp = rand()%num_of_buckets;
            while(find(bipartite_map[i].begin(), bipartite_map[i].end(), temp) != bipartite_map[i].end()){
                temp = rand()%num_of_buckets;
            }
            bipartite_map[i][j] = temp;
        }
    }
}

void bipartiteGraphWeightsGeneration(vector<vector<int>>& bipartite_map, vector<vector<int>>& weights, const int& num_of_transactions, const int& num_of_buckets, const int& repetition, const int& seed){
    srand(seed);
    bipartite_map.clear();
    weights.clear();
    bipartite_map.resize(num_of_transactions);
    weights.resize(num_of_transactions);
    for(int i = 0; i < num_of_transactions; i++)
    {
        bipartite_map[i].resize(repetition, -1);
        weights[i].resize(repetition, -1);
        for(int j = 0; j < repetition; j++){
            int temp = rand()%num_of_buckets;
            while(find(bipartite_map[i].begin(), bipartite_map[i].end(), temp) != bipartite_map[i].end()){
                temp = rand()%num_of_buckets;
            }
            bipartite_map[i][j] = temp;

            weights[i][j] = rand()%65536 + 1;
        }
    }
}

// payloads only has value at first 306 slots, and more specifically, 306 slots if we use 580 bytes
void payloadPacking(Ciphertext& result, const vector<Ciphertext>& payloads, const vector<vector<int>>& bipartite_map, const size_t& degree, 
                        const SEALContext& context, const GaloisKeys& gal_keys, const int payloadSize = 306){
    Evaluator evaluator(context);
    if(payloads.size() != bipartite_map.size())
    {
        cerr << "Something wrong. Payload num should be the same as the bipartite map size." << endl;
        return;
    }

    for(size_t i = 0; i < bipartite_map.size(); i++){
        for(size_t j = 0; j < bipartite_map[i].size(); j++){
            Ciphertext temp; // TODOmulti: if need to parllelize, just switch to vector<Ciphertext> temps(bipartite_map.size()*bipartite_map[i].size()). 
            if(bipartite_map[i][j] < 32) // 32 paylods per row
            {
                auto torotate = degree/2 - bipartite_map[i][j]*payloadSize;
                if((torotate == degree/2))
                    torotate = 0;
                evaluator.rotate_rows(payloads[i], torotate, gal_keys, temp);
            }
            else{
                auto torotate = degree/2 - (bipartite_map[i][j]-32)*payloadSize;
                evaluator.rotate_columns(payloads[i], gal_keys, temp);
                if((torotate == degree/2))
                    torotate = 0;
                evaluator.rotate_rows(temp, torotate, gal_keys, temp);
            }
            if(i == 0 && j == 0)
                result = temp;
            else{
                for(size_t k = 0; k <= j; k++){ // temp should be multipled by j, but since j is usually very small, like 10 or 20 tops, addition is faster
                    evaluator.add_inplace(result, temp); // TODOmulti: addition can be performed in a tree shape
                }
            }
        }
    }
}

// Note that real payload size = payloadSize / 2
void payloadRetrievalOptimizedwithWeights(vector<vector<Ciphertext>>& results, const vector<vector<uint64_t>>& payloads, const vector<vector<int>>& bipartite_map, vector<vector<int>>& weights,
                        const vector<Ciphertext>& SIC, const SEALContext& context, const size_t& degree = 32768, const size_t& start = 0, const size_t& local_start = 0, const int payloadSize = 306){ // TODOmulti: can be multithreaded extremely easily
    Evaluator evaluator(context);
    BatchEncoder batch_encoder(context);
    results.resize(SIC.size());
    // cout << "!!!" << start << " " << local_start << " " << endl;

    for(size_t i = 0; i < SIC.size(); i++){
        // if((i+start == 9000-8192) || (i+start == 9002-8192)){
        //     cout << bipartite_map[i+start] << endl;
        //     cout << weights[i+start] << endl;
        // }
        // cout << payloads[i+local_start][0] << " ";
        // if(start >= 8192)
            // cout << i << " " << start << " " << bipartite_map.size()  << endl;
        results[i].resize(1);
        vector<uint64_t> padded(degree, 0);
        // if(start >= 8192)
            // cout << i << "?" << start << endl;
        for(size_t j = 0; j < bipartite_map[i+start].size(); j++){
            // if(start >= 8192)
                // cout << j << "?" << padded.size() << " " << start << " " << local_start << endl;
            auto paddedStart = bipartite_map[i+start][j]*payloadSize;
            for(size_t k = 0; k < payloads[i+local_start].size(); k++){
                auto toAdd = payloads[i+local_start][k] *weights[i+start][j];
                toAdd %= 65537;
                padded[k+paddedStart] += toAdd;
            }
            // padded.insert(padded.end(), payloads[i+local_start].begin(), payloads[i+local_start].end() );
            // // if(start >= 8192)
            //     // cout << j << "?" << padded.size() << endl;
		    // for(size_t k = 0; k < padded.size(); k++)
		    // 	{padded[k] *= weights[i+start][j]; padded[k] %= 65537;} // weights, to be changed.
            // // if(start >= 8192)
            //     // cout << j << "?" << padded.size() << endl;

        }
        Plaintext plain_matrix;
        batch_encoder.encode(padded, plain_matrix);
        evaluator.transform_to_ntt_inplace(plain_matrix, SIC[i].parms_id());
        // if(start >= 8192)
            // cout << j << "?" << padded.size() << endl;

        evaluator.multiply_plain(SIC[i], plain_matrix, results[i][0]);
        // if(start >= 8192)
            // cout << j << "?" << padded.size() << endl;
        
    }
    // cout << endl;
}

// Note that real payload size = payloadSize / 2
void payloadRetrievalOptimized(vector<vector<Ciphertext>>& results, const vector<vector<uint64_t>>& payloads, const vector<vector<int>>& bipartite_map, 
                        const vector<Ciphertext>& SIC, const SEALContext& context, const size_t& start = 0, const int payloadSize = 306){ // TODOmulti: can be multithreaded extremely easily
    Evaluator evaluator(context);
    BatchEncoder batch_encoder(context);
    results.resize(SIC.size());

    for(size_t i = 0; i < SIC.size(); i++){
        results[i].resize(bipartite_map[i+start].size());
        for(size_t j = 0; j < bipartite_map[i+start].size(); j++){
            vector<uint64_t> padded(bipartite_map[i+start][j]*payloadSize, 0);
            padded.insert(padded.end(), payloads[i+start].begin(), payloads[i+start].end() );
		for(size_t k = 0; k < padded.size(); k++)
			{padded[k] *= int(j+1); padded[k] %= 65537;} // weights, to be changed.

            Plaintext plain_matrix;
            batch_encoder.encode(padded, plain_matrix);

            evaluator.multiply_plain(SIC[i], plain_matrix, results[i][j]);
        }
        
    }
}


void payloadPackingOptimized(Ciphertext& result, const vector<vector<Ciphertext>>& payloads, const vector<vector<int>>& bipartite_map, const size_t& degree, 
                        const SEALContext& context, const GaloisKeys& gal_keys, const size_t& start = 0, const int payloadSize = 306){
    Evaluator evaluator(context);
    //if(payloads.size() != bipartite_map.size())
    //{
    //    cout << "Something wrong. Payload num should be the same as the bipartite map size." << endl;
    //    return;
    //}

    for(size_t i = 0; i < payloads.size(); i++){
        for(size_t j = 0; j < payloads[i].size(); j++){
            if(i == 0 && j == 0 && (start%degree) == 0)
                result = payloads[i][j];
            else{
                for(size_t k = 0; k < 1; k++){ 
                    evaluator.add_inplace(result, payloads[i][j]); 
                }
            }
        }
    }
}

///////////////////////////////////////// MultiThreaded

// MultiThreaded
// one transaction taking one bit
// this takes less than 10^-3 sec per transac, single threaded
void deterministicIndexRetrievalMulti(Ciphertext& indexIndicator, const vector<Ciphertext>& SIC, const SEALContext& context, const size_t& degree, size_t& counter,
                                    const int threadNum = 8){ // counter is used to optimize memory use, not needed for now

    vector<Ciphertext> temp(threadNum);
    Evaluator evaluator(context);

    int interval = (SIC.size() / threadNum);
    int dividor = 0;
    for(int i = threadNum; i > 0; i--){
        if(interval*i + (interval+1)*(threadNum-i) == int(SIC.size()))
            dividor = threadNum - i;
    }
    NTL_EXEC_RANGE(SIC.size(), first, last);
    int indextst = 0;
    for(int index = 0; index < threadNum; index++){
        int first1;
        if(index < dividor){
            first1 = (interval+1)*index;
        }
        else{
            first1 = (interval+1)*dividor + interval*(index-dividor);
        }
        if(last == (int(SIC.size()) - first1))
            indextst = index;
    }
    size_t thecounter = first;
    auto SICslice = std::vector<Ciphertext>(SIC.begin()+first, SIC.begin()+last);
    deterministicIndexRetrieval(temp[indextst], SICslice, context, degree, thecounter, true);
    NTL_EXEC_RANGE_END;

    for(int i = 0; i< threadNum; i++){
        if(i == 0)
            indexIndicator = temp[0];
        else{
            evaluator.add_inplace(indexIndicator, temp[i]); // TODOmulti: addition can be performed in a tree shape
        }
    }
    counter += SIC.size();
}

// Multithreaded
// payloads only has value at first 306 slots, and more specifically, 306 slots if we use 580 bytes
void payloadPackingMulti(Ciphertext& result, const vector<Ciphertext>& payloads, const vector<vector<int>>& bipartite_map, const size_t& degree, 
                        const SEALContext& context, const GaloisKeys& gal_keys, const int payloadSize = 306, const int threadNum = 8){
    Evaluator evaluator(context);
    if(payloads.size() != bipartite_map.size())
    {
        cerr << "Something wrong. Payload num should be the same as the bipartite map size." << endl;
        return;
    }

    vector<Ciphertext> temp(threadNum);
    int interval = (bipartite_map.size() / threadNum);
    int dividor = 0;
    for(int i = threadNum; i > 0; i--){
        if(interval*i + (interval+1)*(threadNum-i) == int(bipartite_map.size()))
            dividor = threadNum - i;
    }

    NTL_EXEC_RANGE(bipartite_map.size(), first, last)
    int indextst = 0;
    for(int index = 0; index < threadNum; index++){
        int first1;
        if(index < dividor){
            first1 = (interval+1)*index;
        }
        else{
            first1 = (interval+1)*dividor + interval*(index-dividor);
        }
        if(last == (int(bipartite_map.size()) - first1))
            indextst = index;
    }
    bool flag = false;
    for(size_t i = first; i < size_t(last); i++){
        for(size_t j = 0; j < bipartite_map[i].size(); j++){
            if(i == 0 && j == 0)
                continue;
            Ciphertext tempsingle; // TODOmulti: if need to parllelize, just switch to vector<Ciphertext> temps(bipartite_map.size()*bipartite_map[i].size()). 
            if(bipartite_map[i][j] < 32) // 32 paylods per row
            {
                auto torotate = degree/2 - bipartite_map[i][j]*payloadSize;
                if((torotate == degree/2))
                    torotate = 0;
                evaluator.rotate_rows(payloads[i], torotate, gal_keys, tempsingle);
            }
            else{
                auto torotate = degree/2 - (bipartite_map[i][j]-32)*payloadSize;
                evaluator.rotate_columns(payloads[i], gal_keys, tempsingle);
                if((torotate == degree/2))
                    torotate = 0;
                evaluator.rotate_rows(tempsingle, torotate, gal_keys, tempsingle);
            }
            if(!flag){
                temp[indextst] = tempsingle;
                flag = true;
                //cout << index -1;
            }
            else{
                for(size_t k = 0; k <= j; k++){ // temp should be multipled by j, but since j is usually very small, like 10 or 20 tops, addition is faster
                    evaluator.add_inplace(temp[indextst], tempsingle); // TODOmulti: addition can be performed in a tree shape
                }
            }
        }
    }
    NTL_EXEC_RANGE_END

    for(int i = 0; i < threadNum; i++){
        if(i == 0)
            result = temp[i];
        else
            evaluator.add_inplace(result, temp[i]); // TODOmulti: addition can be performed in a tree shape
    }
}

void payloadRetrievalMulti(vector<Ciphertext>& results, const vector<vector<uint64_t>>& payloads, const vector<Ciphertext>& SIC, const SEALContext& context
                            , const int threadNum = 8){ // TODOmulti: can be multithreaded extremely easily
    Evaluator evaluator(context);
    BatchEncoder batch_encoder(context);
    results.resize(SIC.size());

    NTL_EXEC_RANGE(SIC.size(), first, last)
    for(size_t i = first; i < uint(last); i++){
        Plaintext plain_matrix;
        batch_encoder.encode(payloads[i], plain_matrix);

        evaluator.multiply_plain(SIC[i], plain_matrix, results[i]);
    }
    NTL_EXEC_RANGE_END
}
