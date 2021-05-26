#pragma once

#include "regevEncryption.h"
#include "palisade.h"
#include <iostream>
using namespace std;
using namespace lbcrypto;

void computeBplusAS(Ciphertext<DCRTPoly>& output, \
        const vector<regevCiphertext>& toPack, const vector<Ciphertext<DCRTPoly>>& switchingKey,\
        const CryptoContext<DCRTPoly>& cryptoContext, const regevParam& param){
        
    for(int i = 0; i < param.n; i++){
        vector<int64_t> vectorOfInts(toPack.size());
        for(size_t j = 0; j < toPack.size(); j++){
            vectorOfInts[j] = toPack[j].a[i].ConvertToInt();
        }
        Plaintext plaintext = cryptoContext->MakePackedPlaintext(vectorOfInts);

        if(i == 0){
            output = cryptoContext->EvalMult(plaintext, switchingKey[i]);
        }
        else{
            Ciphertext<DCRTPoly> temp = cryptoContext->EvalMult(plaintext, switchingKey[i]);
            cryptoContext->EvalAddInPlace(output, temp);
        }
    }

    vector<int64_t> vectorOfInts(toPack.size());
    for(size_t j = 0; j < toPack.size(); j++){
        vectorOfInts[j] = ((toPack[j].b.ConvertToInt() + 16385) % 65537);
    }
    Plaintext plaintext = cryptoContext->MakePackedPlaintext(vectorOfInts);
    output = cryptoContext->EvalSub(plaintext, output);
}

void evalRangeCheck(Ciphertext<DCRTPoly>& output, const int& range, const CryptoContext<DCRTPoly>& cryptoContext, const regevParam& param){
    vector<Ciphertext<DCRTPoly>> ciphertexts(2*range);
    for(int i = 0; i < range; i++){
        vector<int64_t> vectorOfInts(cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder()/2, i+1);
        Plaintext plaintext = cryptoContext->MakePackedPlaintext(vectorOfInts);
        ciphertexts[i] = cryptoContext->EvalAdd(output, plaintext);
    }
    for(int i = 0; i < range; i++){
        vector<int64_t> vectorOfInts(cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder()/2, -i-1);
        Plaintext plaintext = cryptoContext->MakePackedPlaintext(vectorOfInts);
        ciphertexts[i+range] = cryptoContext->EvalAdd(output, plaintext);
    }
    output = cryptoContext->EvalMultMany(ciphertexts);
    
    int i;
    for(i = 1; i < param.q; i*=2){
        // assuming param.q is a power of 2.
        output = cryptoContext->EvalMult(output, output);
    }
}