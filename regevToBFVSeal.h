#pragma once

#include "regevEncryption.h"
#include "seal/seal.h"
using namespace seal;

// takes a vector of ciphertexts, and mult them all together result in the first element of the vector
// depth optimal
inline
void EvalMultMany_inpace(vector<Ciphertext>& ciphertexts, const RelinKeys &relin_keys, const SEALContext& context){ // TODOmulti: can be multithreaded easily
    Evaluator evaluator(context);

    while(ciphertexts.size() != 1){
        for(size_t i = 0; i < ciphertexts.size()/2; i++){
            //if(i % 100 == 0)
            //    cout << "hello " << i << endl;
            evaluator.multiply_inplace(ciphertexts[i], ciphertexts[ciphertexts.size()/2+i]);
            evaluator.relinearize_inplace(ciphertexts[i], relin_keys);
            evaluator.mod_switch_to_next_inplace(ciphertexts[i]);
        }
        if(ciphertexts.size()%2 == 0)
            ciphertexts.resize(ciphertexts.size()/2);
        else{ // if odd, take the last one and mod down to make them compatible
            ciphertexts[ciphertexts.size()/2] = ciphertexts[ciphertexts.size()-1];
            evaluator.mod_switch_to_next_inplace(ciphertexts[ciphertexts.size()/2]);
            ciphertexts.resize(ciphertexts.size()/2+1);
        }
    }
}

// Takes a ciphertexts
// return c^65536, depth optimal
void booleanization(Ciphertext& ciphertext, const RelinKeys &relin_keys, const SEALContext& context, const int& modulus_p = 65537){
    if(modulus_p == 65537){
        Evaluator evaluator(context);
        for(int i = 0; i < 16; i++){
            evaluator.multiply_inplace(ciphertext,ciphertext);
            evaluator.relinearize_inplace(ciphertext, relin_keys);
            evaluator.mod_switch_to_next_inplace(ciphertext);
        }
    }
    else{
        cerr << "Implementation for other modulus not implemented" << endl;
    }
}

// take regev sk's and output switching key, which is a ciphertext of size n, where n is the regev ciphertext dimension
void genSwitchingKey(vector<Ciphertext>& switchingKey, const SEALContext& context, const size_t& degree,\
                         const PublicKey& BFVpk, const regevSK& regSk, const regevParam& params){ // TODOmulti: can be multithreaded easily
    BatchEncoder batch_encoder(context);
    Encryptor encryptor(context, BFVpk);
    switchingKey.resize(params.n);
    for(int i = 0; i < params.n; i++){
        vector<uint64_t> skInt(degree, uint64_t(regSk[i].ConvertToInt() % 65537));
        Plaintext plaintext;
        batch_encoder.encode(skInt, plaintext);
        encryptor.encrypt(plaintext, switchingKey[i]);
    }
}

// compute b - as
void computeBplusAS(Ciphertext& output, \
        const vector<regevCiphertext>& toPack, const vector<Ciphertext>& switchingKey,\
        const SEALContext& context, const regevParam& param){ // TODOmulti: can be multithreaded, not that easily, but doable


    Evaluator evaluator(context);
    BatchEncoder batch_encoder(context);
    size_t slot_count = batch_encoder.slot_count();
    if(toPack.size() > slot_count){
        cerr << "Please pack at most " << slot_count << " regev ciphertexts at one time." << endl;
        return;
    }
        
    for(int i = 0; i < param.n; i++){
        //if (i % 100 == 0){
        //    cout << "computeBplusAS: " << i << endl;
        //}
        vector<uint64_t> vectorOfInts(toPack.size());
        for(size_t j = 0; j < toPack.size(); j++){
            vectorOfInts[j] = uint64_t((toPack[j].a[i].ConvertToInt())); // store at most degree amount of a[i]'s
        }
        Plaintext plaintext;
        batch_encoder.encode(vectorOfInts, plaintext);

        if(i == 0){
            evaluator.multiply_plain(switchingKey[i], plaintext, output); // times s[i]
        }
        else{
            Ciphertext temp;
            evaluator.multiply_plain(switchingKey[i], plaintext, temp);
            evaluator.add_inplace(output, temp);
        }
    }

    vector<uint64_t> vectorOfInts(toPack.size());
    for(size_t j = 0; j < toPack.size(); j++){
        vectorOfInts[j] = uint64_t((toPack[j].b.ConvertToInt() - 16384) % 65537); // b - sum(s[i]a[i])
    }
    Plaintext plaintext;
    batch_encoder.encode(vectorOfInts, plaintext);
    evaluator.negate_inplace(output);
    evaluator.add_plain_inplace(output, plaintext);
}

// check in range
// if within [-range, range -1], returns 0, and returns random number in p o/w
void evalRangeCheck(Ciphertext& output, const int& range, const RelinKeys &relin_keys,\
                        const size_t& degree, const SEALContext& context, const regevParam& param){
    Evaluator evaluator(context);
    BatchEncoder batch_encoder(context);
    vector<Ciphertext> ciphertexts(2*range);
    for(int i = 0; i < range; i++){
        vector<uint64_t> vectorOfInts(degree, i+1); // check for up to -range
        Plaintext plaintext;
        batch_encoder.encode(vectorOfInts, plaintext);
        evaluator.add_plain(output, plaintext, ciphertexts[i]);
    }
    for(int i = 0; i < range; i++){
        vector<uint64_t> vectorOfInts(degree, 65537 - i); // check for up to range - 1, because we include 0 in this 
        Plaintext plaintext;
        batch_encoder.encode(vectorOfInts, plaintext);
        evaluator.add_plain(output, plaintext, ciphertexts[range+i]);
    }
    //cout << "range compute finished" << endl;
    EvalMultMany_inpace(ciphertexts, relin_keys, context);
    output = ciphertexts[0];
    
    booleanization(output, relin_keys, context);
}

// check in range
// if within [-range, range -1], returns 0, and returns random number in p o/w
void evalRangeCheckMemorySaving(Ciphertext& output, const int& range, const RelinKeys &relin_keys,\
                        const size_t& degree, const SEALContext& context, const regevParam& param, const int upperbound = 64){ // we do one level of recursion, so no more than 4096 elements
    Evaluator evaluator(context);
    BatchEncoder batch_encoder(context);
    vector<Ciphertext> ciphertexts(upperbound);
    vector<Ciphertext> res(range*2/upperbound);
    int counter = 0;
    int counter2 = 0;
    for(int i = 0; i < range; i++){
        vector<uint64_t> vectorOfInts(degree, i+1); // check for up to -range
        Plaintext plaintext;
        batch_encoder.encode(vectorOfInts, plaintext);
        evaluator.add_plain(output, plaintext, ciphertexts[counter++]);
        cout << i << endl;
        if(counter == 64){
            EvalMultMany_inpace(ciphertexts, relin_keys, context);
            res[counter2++] = ciphertexts[0];
            counter = 0;
            ciphertexts.resize(0);
            ciphertexts.resize(upperbound);
        }
    }
    for(int i = 0; i < range; i++){
        vector<uint64_t> vectorOfInts(degree, 65537 - i); // check for up to range - 1, because we include 0 in this 
        Plaintext plaintext;
        batch_encoder.encode(vectorOfInts, plaintext);
        evaluator.add_plain(output, plaintext, ciphertexts[counter++]);
        cout << i << endl;
        if(counter == 64){
            EvalMultMany_inpace(ciphertexts, relin_keys, context);
            res[counter2++] = ciphertexts[0];
            counter = 0;
            ciphertexts.resize(0);
            ciphertexts.resize(upperbound);
        }
    }
    cout << "range compute finished" << endl;
    EvalMultMany_inpace(res, relin_keys, context);
    output = res[0];
    
    booleanization(output, relin_keys, context);
}

// innersum up to toCover amount, O(log(toCover)) time
void innerSum_inplace(Ciphertext& output, const GaloisKeys& gal_keys, const size_t& degree,
                const size_t& toCover, const SEALContext& context){
    Evaluator evaluator(context);
    for(size_t i = 1; i < toCover; i*=2){
        Ciphertext temp;
        if(i == degree/2)
        {
            evaluator.rotate_columns(output, gal_keys, temp);
            evaluator.add_inplace(output, temp);
        }
        else
        {
            evaluator.rotate_rows(output, degree/2 - i, gal_keys, temp);
            evaluator.add_inplace(output, temp);
        }
    }
}

// Takes one SIC compressed and expand then into SIC's each encrypt 0/1 in slots up to cover 580 bytes
void expandSIC(vector<Ciphertext>& expanded, Ciphertext& toExpand, const GaloisKeys& gal_keys,
                const size_t& degree, const SEALContext& context, const size_t& toExpandNum){ 
    BatchEncoder batch_encoder(context);
    Evaluator evaluator(context);
    expanded.resize(toExpandNum);

    vector<uint64_t> pod_matrix(degree, 0ULL); // TODOmulti: move inside to do multi-threading.
    pod_matrix[0] = 1ULL;
    Plaintext plain_matrix;
    batch_encoder.encode(pod_matrix, plain_matrix);
    for(size_t i = 0; i < toExpandNum; i++){ // TODOmulti: change to do multi-threading.
        if(i != 0){ // if not 0, need to rotate to place 0
            if(i == degree/2){
                evaluator.rotate_columns_inplace(toExpand, gal_keys);
            }
            else{
                evaluator.rotate_rows_inplace(toExpand, 1, gal_keys);
            }
        }
        evaluator.multiply_plain(toExpand, plain_matrix, expanded[i]);
        innerSum_inplace(expanded[i], gal_keys, degree, 32768, context); // This is to make future work less, and slowing by less than double for now.
        //innerSum_inplace(expanded[i], gal_keys, degree, 290, context); // 580 bytes, and each slot 2 bytes, so totally 290 slots. Can get up to 1KB
    }
}