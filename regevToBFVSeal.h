#pragma once

#include "regevEncryption.h"
#include "seal/seal.h"
using namespace seal;

void EvalMultMany_inpace(vector<Ciphertext>& ciphertexts, const RelinKeys &relin_keys, const SEALContext& context){
    Evaluator evaluator(context);

    while(ciphertexts.size() != 1){
        for(size_t i = 0; i < ciphertexts.size()/2; i++){
            if(i % 100 == 0)
                cout << "hello " << i << endl;
            evaluator.multiply_inplace(ciphertexts[i], ciphertexts[ciphertexts.size()/2+i]);
            evaluator.relinearize_inplace(ciphertexts[i], relin_keys);
            evaluator.mod_switch_to_next_inplace(ciphertexts[i]);
        }
        if(ciphertexts.size()%2 == 0)
            ciphertexts.resize(ciphertexts.size()/2);
        else{
            ciphertexts[ciphertexts.size()/2] = ciphertexts[ciphertexts.size()-1];
            evaluator.mod_switch_to_next_inplace(ciphertexts[ciphertexts.size()/2]);
            ciphertexts.resize(ciphertexts.size()/2+1);
        }
    }
}

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

void genSwitchingKey(vector<Ciphertext>& switchingKey, const SEALContext& context, const size_t& degree,\
                         const PublicKey& BFVpk, const regevSK& regSk, const regevParam& params){
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

void computeBplusAS(Ciphertext& output, \
        const vector<regevCiphertext>& toPack, const vector<Ciphertext>& switchingKey,\
        const SEALContext& context, const regevParam& param){


    Evaluator evaluator(context);
    BatchEncoder batch_encoder(context);
    size_t slot_count = batch_encoder.slot_count();
    if(toPack.size() > slot_count){
        cerr << "Please pack at most " << slot_count << " regev ciphertexts at one time." << endl;
        return;
    }
        
    for(int i = 0; i < param.n; i++){
        if (i % 100 == 0){
            cout << "computeBplusAS: " << i << endl;
        }
        vector<uint64_t> vectorOfInts(toPack.size());
        for(size_t j = 0; j < toPack.size(); j++){
            vectorOfInts[j] = uint64_t((toPack[j].a[i].ConvertToInt()));
        }
        Plaintext plaintext;
        batch_encoder.encode(vectorOfInts, plaintext);

        if(i == 0){
            evaluator.multiply_plain(switchingKey[i], plaintext, output);
        }
        else{
            Ciphertext temp;
            evaluator.multiply_plain(switchingKey[i], plaintext, temp);
            evaluator.add_inplace(output, temp);
        }
    }

    vector<uint64_t> vectorOfInts(toPack.size());
    for(size_t j = 0; j < toPack.size(); j++){
        vectorOfInts[j] = uint64_t((toPack[j].b.ConvertToInt() - 16384) % 65537);
    }
    Plaintext plaintext;
    batch_encoder.encode(vectorOfInts, plaintext);
    evaluator.negate_inplace(output);
    evaluator.add_plain_inplace(output, plaintext);
}

void evalRangeCheck(Ciphertext& output, const int& range, const RelinKeys &relin_keys,\
                        const size_t& degree, const SEALContext& context, const regevParam& param){
    Evaluator evaluator(context);
    BatchEncoder batch_encoder(context);
    vector<Ciphertext> ciphertexts(2*range);
    for(int i = 0; i < range; i++){
        vector<uint64_t> vectorOfInts(degree, i+1);
        Plaintext plaintext;
        batch_encoder.encode(vectorOfInts, plaintext);
        evaluator.add_plain(output, plaintext, ciphertexts[i]);
    }
    for(int i = 0; i < range; i++){
        vector<uint64_t> vectorOfInts(degree, 65537 - i);
        Plaintext plaintext;
        batch_encoder.encode(vectorOfInts, plaintext);
        evaluator.add_plain(output, plaintext, ciphertexts[range+i]);
    }
    cout << "range compute finished" << endl;
    EvalMultMany_inpace(ciphertexts, relin_keys, context);
    output = ciphertexts[0];
    
    booleanization(output, relin_keys, context);
}