#pragma once

#include "regevToBFVSeal.h"
#include <algorithm>

// one transaction taking one bit
// this takes less than 10^-3 sec per transac, single threaded
void deterministicIndexRetrieval(Ciphertext& indexIndicator, const vector<Ciphertext>& SIC, const SEALContext& context, const size_t& degree, size_t& counter){ // counter is used to optimize memory use, not needed for now
    BatchEncoder batch_encoder(context);
    Evaluator evaluator(context);
    vector<uint64_t> pod_matrix(degree, 0ULL); // TODOmulti: move inside to the loop for multi-threading
    if(counter + SIC.size() >= 16*degree){
        cout << "counter + SIC.size should be less, please check" << endl;
        return;
    }

    for(size_t i = 0; i < SIC.size(); i++){
        size_t idx = counter/16; // modulus is 65537, so we can support at most 16 bits per slot
        size_t shift = counter % 16;
        pod_matrix[idx] = (1<<shift);
        Plaintext plain_matrix;
        batch_encoder.encode(pod_matrix, plain_matrix);

        if(i == 0){
            evaluator.multiply_plain(SIC[i], plain_matrix, indexIndicator);
        }
        else{
            Ciphertext temp;
            evaluator.multiply_plain(SIC[i], plain_matrix, temp);
            evaluator.add_inplace(indexIndicator, temp);
        }
        pod_matrix[idx] = 0ULL;
        counter++;
    }
}

vector<int> randomizedIndexRetrieval(Ciphertext& indexIndicator, const vector<Ciphertext>& SIC, const SEALContext& context, const size_t& degree, size_t& counter, const int& seed){ // counter is used to optimize memory use, not needed for now
    srand(seed);
    BatchEncoder batch_encoder(context);
    Evaluator evaluator(context);
    vector<uint64_t> pod_matrix(degree, 0ULL); // TODOmulti: move inside to the loop for multi-threading
    vector<int> rand_map(SIC.size());
    for(size_t i = 0; i < SIC.size(); i++){
        rand_map[i] = rand()%(16*degree);
        size_t idx = rand_map[i]/16; // modulus is 65537, so we can support at most 16 bits per slot
        size_t shift = rand_map[i]%16;
        pod_matrix[idx] = (1<<shift);
        Plaintext plain_matrix;
        batch_encoder.encode(pod_matrix, plain_matrix);

        if(i == 0){
            evaluator.multiply_plain(SIC[i], plain_matrix, indexIndicator);
        }
        else{
            Ciphertext temp;
            evaluator.multiply_plain(SIC[i], plain_matrix, temp);
            evaluator.add_inplace(indexIndicator, temp);
        }
        pod_matrix[idx] = 0ULL;
        counter++;
    }
    return rand_map; // It's the same to just maintain the seed. This is just for implementation easiness.
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

// payloads only has value at first 512 slots, and more specifically, 290 slots if we use 580 bytes
void payloadPacking(Ciphertext& result, const vector<Ciphertext>& payloads, const vector<vector<int>>& bipartite_map, const size_t& degree, const SEALContext& context, const GaloisKeys& gal_keys){
    Evaluator evaluator(context);
    if(payloads.size() != bipartite_map.size())
    {
        cout << "Something wrong. Payload num should be the same as the bipartite map size." << endl;
        return;
    }

    for(size_t i = 0; i < bipartite_map.size(); i++){
        for(size_t j = 0; j < bipartite_map[i].size(); j++){
            Ciphertext temp; // TODOmulti: if need to parllelize, just switch to vector<Ciphertext> temps(bipartite_map.size()*bipartite_map[i].size()). 
            if(bipartite_map[i][j] < 32) // 32 paylods per row
            {
                auto torotate = degree/2 - bipartite_map[i][j]*512;
                if((torotate == degree/2))
                    torotate = 0;
                evaluator.rotate_rows(payloads[i], torotate, gal_keys, temp);
            }
            else{
                auto torotate = degree/2 - (bipartite_map[i][j]-32)*512;
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