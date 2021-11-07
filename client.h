#pragma once

#include "seal/seal.h"
#include <algorithm>  
#include <map>

using namespace seal;
#define PROFILE

void decodeIndices(map<int, int>& pertinentIndices, const Ciphertext& indexPack, const int& num_of_transactions, const size_t& degree, const SecretKey& secret_key, const SEALContext& context){
    // TimeVar t;
    // TIC(t);
    Decryptor decryptor(context, secret_key);
    BatchEncoder batch_encoder(context);
    vector<uint64_t> indexPackint(degree);
    Plaintext plain_result;
    decryptor.decrypt(indexPack, plain_result);
    batch_encoder.decode(plain_result, indexPackint);
    // cout << TOC_US(t) << endl;
    // cout << "???" << endl;
    int counter = 0;
    int backcounter = 16;
    int idx = 0;
    // TIC(t);
    for(int i = 0; i < num_of_transactions;){
        if(!indexPackint[idx])
        {
            // cout << idx << endl;
            idx += 1;
            i += backcounter;
            backcounter = 16;
            continue;
        }
        // int shift = i % 16;
        if(indexPackint[idx]&1) // check if that slot is 1
        {
            pertinentIndices.insert(pair<int, int>(i, counter++));
        }
        indexPackint[idx] >>= 1;
        backcounter -= 1;
        i++;
    }
    // cout << TOC_US(t) << endl;
    // cout << "???" << endl;
}

void decodeIndicesRandom(map<int, int>& pertinentIndices, const vector<vector<Ciphertext>>& indexPack, const vector<Ciphertext>& indexCounter,
                                     const size_t& degree, const SecretKey& secret_key, const SEALContext& context){
    Decryptor decryptor(context, secret_key);
    BatchEncoder batch_encoder(context);

    int counter = 0;
    int realNumOfPertinentMsg = 0;
    vector<uint64_t> countertemp(degree);
    Plaintext plain_result;
    decryptor.decrypt(indexCounter[0], plain_result);
    batch_encoder.decode(plain_result, countertemp);
    for(size_t i = 0; i < degree; i++){
        realNumOfPertinentMsg += countertemp[i];
    }

    for(size_t i = 0; i < indexCounter.size(); i++){
        vector<uint64_t> plain_counter(degree), plain_one(degree), plain_two(degree);
        decryptor.decrypt(indexCounter[i], plain_result);
        batch_encoder.decode(plain_result, plain_counter);
        decryptor.decrypt(indexPack[i][0], plain_result);
        batch_encoder.decode(plain_result, plain_one);
        decryptor.decrypt(indexPack[i][1], plain_result);
        batch_encoder.decode(plain_result, plain_two);
        for(size_t j = 0; j < degree; j++){
            if(plain_counter[j] == 1){
                uint64_t index = plain_one[j]*65537 + plain_two[j];
                if(pertinentIndices.find(index) == pertinentIndices.end()){
                    pertinentIndices.insert(pair<int, int>(index, counter++));
                }
            }
        }
        if(counter == realNumOfPertinentMsg)
            break;
    }
    if(counter != realNumOfPertinentMsg)
    {
        cerr << "Overflow" << endl;
        exit(1);
    }
}

void formRhs(vector<vector<int>>& rhs, const Ciphertext& packedPayloads, const SecretKey& secret_key, const size_t& degree, const SEALContext& context,
                         const int num_of_buckets = 64, const int payloadSlots = 306){ // or 306
    Decryptor decryptor(context, secret_key);
    BatchEncoder batch_encoder(context);
    vector<uint64_t> rhsint(degree);
    Plaintext plain_result;
    decryptor.decrypt(packedPayloads, plain_result);
    batch_encoder.decode(plain_result, rhsint);

    rhs.resize(num_of_buckets);
    for(int i = 0; i < num_of_buckets; i++){
        rhs[i].resize(payloadSlots, 0);
    }
    for(int i = 0; i < num_of_buckets; i++){
        for(int j = 0; j < payloadSlots; j++){
            rhs[i][j] = int(rhsint[i*payloadSlots + j]);
        }
    }
    // for(size_t i = 0; i < rhs.size(); i++){
    //     for(size_t j = 0; j < rhs[i].size(); j++)
    //         cout << rhs[i][j] << " ";
    //     cout << endl;
    // }
}

void formLhs(vector<vector<int>>& lhs, map<int, int>& pertinentIndices, const vector<vector<int>>& bipartite_map,
                            const int start = 0, const int num_of_buckets = 64){ // the last two parameters are for more buckets
    auto pertinentTransactionNum = pertinentIndices.size();
    lhs.resize(num_of_buckets);
    for(int i = 0; i < num_of_buckets; i++){
        lhs[i].resize(pertinentTransactionNum);
    }

    map<int, int>::iterator itr;
    for(itr = pertinentIndices.begin(); itr != pertinentIndices.end(); ++itr){
        auto ptr = &bipartite_map[itr->first];
        for(size_t j = 0; j < ptr->size(); j++){
            lhs[(*ptr)[j]][itr->second] = j + 1; // j can be replaced. need to reimplement
        }

    }
}

void formLhsWeights(vector<vector<int>>& lhs, map<int, int>& pertinentIndices, const vector<vector<int>>& bipartite_map, vector<vector<int>>& weights,
                            const int start = 0, const int num_of_buckets = 64){ // the last two parameters are for more buckets
    // cout << "weights! " << endl;
    auto pertinentTransactionNum = pertinentIndices.size();
    lhs.resize(num_of_buckets);
    for(int i = 0; i < num_of_buckets; i++){
        lhs[i].resize(pertinentTransactionNum);
    }
    // cout << bipartite_map[9000-8192] << endl;
    // cout << bipartite_map[9002-8192] << endl;
    // cout << weights[9000-8192] << endl;
    // cout << weights[9002-8192] << endl;



    map<int, int>::iterator itr;
    for(itr = pertinentIndices.begin(); itr != pertinentIndices.end(); ++itr){
        auto ptr = &bipartite_map[itr->first];
        // cout << bipartite_map[itr->first] << endl;
        // cout << itr->first << endl;
        for(size_t j = 0; j < ptr->size(); j++){
            lhs[(*ptr)[j]][itr->second] = weights[itr->first][j]; // j can be replaced. need to reimplement
        }

    }
    // for(size_t i = 0; i < lhs.size(); i++){
    //     for(size_t j = 0; j < lhs[i].size(); j++)
    //         cout << lhs[i][j] << " ";
    //     cout << endl;
    // }
}


/////////////////////////// For equation solving

inline
void mult_scalar_vec(vector<int>& output, const vector<int>& input, int k){
    output.resize(input.size());
    for(size_t i = 0; i < output.size(); i++){
        long temp = ((long)input[i]*(long)k)%65537;
        output[i] = temp;
        if(output[i] < 0)
            cerr <<temp << " " << k << " " << input[i] << endl;
    } 
}

inline
void subtract_two_vec_inplace(vector<int>& output, const vector<int>& input, int numToSolve = -1){
    if(output.size() != input.size())
    {
        cerr << "substracting size not equal." << endl;
    }
    if(numToSolve == -1) numToSolve = input.size();
    for(int i = 0; i < numToSolve; i++){
        output[i] -= input[i];
        output[i] %= 65537; // modulus
        while(output[i] < 0){
            output[i] += 65537;
        }

    }
}
 
// To compute x^y under modulo m
inline
long power(long x, long y, long m)
{
    if (y == 0)
        return 1;
    long p = power(x, y / 2, m) % m;
    p = (p * p) % m;
 
    return (y % 2 == 0) ? p : (x * p) % m;
}

inline
long modInverse(long a, long m)
{
    return power(a, m - 2, m);
}

inline
long div_mod(long a, long b, long mod = 65537){
    return (a*modInverse(b, mod)) % mod;
    // returns a*(b^-1) mod 65537
}

inline
void get_ratio_mult_and_subtract(vector<int>& output, const vector<int>& input, const int& whichItem, const int& numToSolve, int& k){
    vector<int> temp(input.size());
    if(k == -1){
        k = div_mod(output[whichItem], input[whichItem]);
        mult_scalar_vec(temp, input, k);
        subtract_two_vec_inplace(output, temp);
    }
    else{
        mult_scalar_vec(temp, input, k);
        subtract_two_vec_inplace(output, temp, numToSolve);
    }
    
}

inline
vector<long> singleSolve(const long& a, const vector<int>& toSolve, long mod = 65537){
    long a_rev = modInverse(a, mod);
    vector<long> res(toSolve.size());
    for(size_t i = 0; i < toSolve.size(); i++){
        res[i] = ((long)toSolve[i] * a_rev) % 65537;
    }
    return res;
}

vector<vector<long>> equationSolving(vector<vector<int>>& lhs, vector<vector<int>>& rhs, const int& numToSolve = 306){
    vector<int> recoder(lhs[0].size(), -1);
    size_t counter = 0;
    int rcd = 0;

    while(counter < recoder.size()){
        for(size_t i = 0; i < lhs.size(); i++){
            if (lhs[i][counter] != 0){
                if(find(recoder.begin(), recoder.end(), int(i)) != recoder.end()){
                    continue;
                }
                recoder[counter] = i;
                rcd = lhs[i][counter];
                break;
            }
        }
        if(recoder[counter] == -1){
            cerr << "no solution" << endl;
            return vector<vector<long>>(0);
        }
        for(size_t i = 0; i < lhs.size(); i++){
            if ((lhs[i][counter] != 0) && (lhs[i][counter] != rcd))
            {
                int k = -1;
                get_ratio_mult_and_subtract(lhs[i], lhs[recoder[counter]], counter, numToSolve, k);
                get_ratio_mult_and_subtract(rhs[i], rhs[recoder[counter]], counter, numToSolve, k);
            }
        }
        counter++;
    }

    vector<vector<long>> res(recoder.size());
    counter = 0;
    for(size_t i = 0; i < recoder.size(); i++){
        res[i] = singleSolve(lhs[recoder[counter]][counter], rhs[recoder[counter]]);
        counter++;
    }
    return res;
}