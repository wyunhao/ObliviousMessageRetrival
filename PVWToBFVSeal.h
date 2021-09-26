
#pragma once

#include "regevToBFVSeal.h"
#include "regevEncryption.h"
#include "seal/seal.h"
#include <NTL/BasicThreadPool.h>
using namespace seal;

// take PVW sk's and output switching key, which is a ciphertext of size \ell*n, where n is the PVW ciphertext dimension
void genSwitchingKeyPVW(vector<vector<Ciphertext>>& switchingKey, const SEALContext& context, const size_t& degree,\
                         const PublicKey& BFVpk, const PVWsk& regSk, const PVWParam& params){ // TODOmulti: can be multithreaded easily
    BatchEncoder batch_encoder(context);
    Encryptor encryptor(context, BFVpk);
    switchingKey.resize(params.ell);
    for(int j = 0; j < params.ell; j++){
        switchingKey[j].resize(params.n);
        for(int i = 0; i < params.n; i++){
            // cout << i << endl;
            vector<uint64_t> skInt(degree, uint64_t(regSk[j][i].ConvertToInt() % 65537));
            Plaintext plaintext;
            batch_encoder.encode(skInt, plaintext);
            encryptor.encrypt(plaintext, switchingKey[j][i]);
        }
    }
}

// compute b - as
void computeBplusASPVW(vector<Ciphertext>& output, \
        const vector<PVWCiphertext>& toPack, const vector<vector<Ciphertext>>& switchingKey,\
        const SEALContext& context, const PVWParam& param){ // TODOmulti: can be multithreaded, not that easily, but doable


    Evaluator evaluator(context);
    BatchEncoder batch_encoder(context);
    size_t slot_count = batch_encoder.slot_count();
    if(toPack.size() > slot_count){
        cerr << "Please pack at most " << slot_count << " PVW ciphertexts at one time." << endl;
        return;
    }
    output.resize(param.ell);

    for(int i = 0; i < param.n; i++){

        // cout << i << " " << toPack.size() << endl;
        //if (i % 100 == 0){
        //    cout << "computeBplusAS: " << i << endl;
        //}
        vector<uint64_t> vectorOfInts(toPack.size());
        for(size_t j = 0; j < toPack.size(); j++){
            vectorOfInts[j] = uint64_t((toPack[j].a[i].ConvertToInt())); // store at most degree amount of a[i]'s
        }
        Plaintext plaintext;
        batch_encoder.encode(vectorOfInts, plaintext);
        
        for(int j = 0; j < param.ell; j++){
            if(i == 0){
                evaluator.multiply_plain(switchingKey[j][i], plaintext, output[j]); // times s[i]
            }
            else{
                Ciphertext temp;
                evaluator.multiply_plain(switchingKey[j][i], plaintext, temp);
                evaluator.add_inplace(output[j], temp);
            }
        }
    }

    for(int i = 0; i < param.ell; i++){
        vector<uint64_t> vectorOfInts(toPack.size());
        for(size_t j = 0; j < toPack.size(); j++){
            vectorOfInts[j] = uint64_t((toPack[j].b[i].ConvertToInt() - 16384) % 65537); // b - sum(s[i]a[i])
        }
        Plaintext plaintext;

        batch_encoder.encode(vectorOfInts, plaintext);
        evaluator.negate_inplace(output[i]);
        evaluator.add_plain_inplace(output[i], plaintext);
    }
}

// check in range
// if within [-range, range -1], returns 0, and returns random number in p o/w
void evalRangeCheckMemorySavingOptimizedPVW(vector<Ciphertext>& output, const int& range, const RelinKeys &relin_keys,\
                        const size_t& degree, const SEALContext& context, const PVWParam& param, const int upperbound = 64){ // we do one level of recursion, so no more than 4096 elements
    Evaluator evaluator(context);
    BatchEncoder batch_encoder(context);

    for(int j = 0; j < param.ell; j++){
        vector<Ciphertext> ciphertexts(upperbound);
        vector<Ciphertext> res(range*2/upperbound);
        int counter = 0;
        int counter2 = 0;
        // evaluator.mod_switch_to_next_inplace(output);
        evaluator.square_inplace(output[j]);
        evaluator.relinearize_inplace(output[j], relin_keys);
        evaluator.mod_switch_to_next_inplace(output[j]);

        for(int i = 0; i < range; i++){
            int squared = (i*i)%65537;
            if(i != 0)
                squared = 65537-squared;
            
            vector<uint64_t> vectorOfInts(degree, uint64_t(squared)); // check for up to -range
            Plaintext plaintext;
            batch_encoder.encode(vectorOfInts, plaintext);
            evaluator.add_plain(output[j], plaintext, ciphertexts[counter++]);
            // cout << i << endl;
            if(counter == 64){
                EvalMultMany_inpace(ciphertexts, relin_keys, context);
                res[counter2++] = ciphertexts[0];
                counter = 0;
                ciphertexts.resize(0);
                ciphertexts.resize(upperbound);
            }
        }
        cout << "range compute finished" << endl;
        if(counter != 0){
            cout << counter << "\n";
            ciphertexts.resize(counter);
            EvalMultMany_inpace(ciphertexts, relin_keys, context);
            res[counter2++] = ciphertexts[0];
            for(auto i = counter; i <= upperbound/2; i *=2)
                evaluator.mod_switch_to_next_inplace(res[counter2-1]);
            counter = 0;
            ciphertexts.resize(0);
            ciphertexts.resize(upperbound);
        }
        if(counter2 > 1){
            res.resize(counter2);
            EvalMultMany_inpace(res, relin_keys, context);
        }
        output[j] = res[0];
    }

    if(param.ell == 4){
        for(int j = 0; j < 2; j++){
            evaluator.add_inplace(output[j], output[j+2]);
            // evaluator.mod_switch_to_next_inplace(output[j]); // XXX
            booleanization(output[j], relin_keys, context);
            Plaintext plaintext;
            vector<uint64_t> vectorOfInts(degree, 1);
            batch_encoder.encode(vectorOfInts, plaintext);
            evaluator.negate_inplace(output[j]);
            evaluator.add_plain_inplace(output[j], plaintext);
        }
        evaluator.multiply_inplace(output[0], output[1]);
        evaluator.relinearize_inplace(output[0], relin_keys);
        evaluator.mod_switch_to_next_inplace(output[0]);
        output.resize(1);
    } else {
        // not implemented
        return; 
    }
}

inline
void calUptoDegreeK(vector<Ciphertext>& output, const Ciphertext& input, const int DegreeK, const RelinKeys &relin_keys, const SEALContext& context){
    vector<int> calculated(DegreeK, 0);
    Evaluator evaluator(context);
    output.resize(DegreeK);
    output[0] = input;
    calculated[0] = 1; // degree 1, x
    Ciphertext res, base;

    for(int i = DegreeK; i > 0; i--){
        if(calculated[i-1] == 0){
            auto toCalculate = i;
            int resdeg = 0;
            int basedeg = 1;
            base = input;
            while(toCalculate > 0){
                if(toCalculate & 1){
                    toCalculate -= 1;
                    resdeg += basedeg;
                    if(calculated[resdeg-1] != 0){
                        res = output[resdeg - 1];
                    } else {
                        if(resdeg == basedeg){
                            res = base; // should've never be used as base should have made calculated[basedeg-1]
                        } else {
                            evaluator.mod_switch_to_inplace(res, base.parms_id()); // match modulus
                            evaluator.multiply_inplace(res, base);
                            evaluator.relinearize_inplace(res, relin_keys);
                            evaluator.mod_switch_to_next_inplace(res);
                        }
                        output[resdeg-1] = res;
                        calculated[resdeg-1] += 1;
                    }
                } else {
                    toCalculate /= 2;
                    basedeg *= 2;
                    if(calculated[basedeg-1] != 0){
                        base = output[basedeg - 1];
                    } else {
                        evaluator.square_inplace(base);
                        evaluator.relinearize_inplace(base, relin_keys);
                        evaluator.mod_switch_to_next_inplace(base);
                        output[basedeg-1] = base;
                        calculated[basedeg-1] += 1;
                    }
                }
            }
        }
    }

    for(size_t i = 0; i < output.size()-1; i++){
        evaluator.mod_switch_to_inplace(output[i], output[output.size()-1].parms_id()); // match modulus
    }
    return;
}

template <typename T> // from: https://stackoverflow.com/questions/8496182/calculating-powa-b-mod-n/8498251
T modpow(T base, T exp, T modulus) {
  base %= modulus;
  T result = 1;
  while (exp > 0) {
    if (exp & 1) result = (result * base) % modulus;
    base = (base * base) % modulus;
    exp >>= 1;
  }
  return result;
}

inline
void calIndices(vector<uint64_t>& output, uint64_t p = 65537){
    output.resize(p-1, 0);
    for(uint64_t i = 1; i < p-1; i+=2){
        for(uint64_t j = 0; j < (p-1)/2+1; j++){
            output[i] += modpow(j, p-1-i, p);
            output[i] %= p;
        }
    }
}

inline
void lessThan_PatersonStockmeyer(Ciphertext& ciphertext, const Ciphertext& input, int modulus, const size_t& degree,
                                const RelinKeys &relin_keys, const SEALContext& context){
    Evaluator evaluator(context);
    BatchEncoder batch_encoder(context);
    vector<Ciphertext> kCTs;
    calUptoDegreeK(kCTs, input, 256, relin_keys, context);
    vector<Ciphertext> kToMCTs;
    calUptoDegreeK(kToMCTs, kCTs[kCTs.size()-1], 256, relin_keys, context);
    
    for(size_t j = 0; j < kCTs.size(); j++){ // match to one level left, the one level left is for plaintext multiplication noise
        for(int i = 0; i < 8; i++){
            evaluator.mod_switch_to_next_inplace(kCTs[j]);
        }
        evaluator.mod_switch_to_next_inplace(kToMCTs[j]);
    }

    for(int i = 0; i < 256; i++){
        // cout << i << ": ";
        Ciphertext levelSum;
        bool flag = false;
        for(int j = 0; j < 256; j++){
            if(LTindices[i*256+j] != 0){    
                // cout << j <<",";
                // cout << i << " " << j << " " << LTindices[i*256+j] << endl;
                vector<uint64_t> intInd(degree, LTindices[i*256+j]);
                Plaintext plainInd;
                batch_encoder.encode(intInd, plainInd);
                if(j % 2 == 0){
                    cout << "Should not be even indices" << endl;
                    if(i*256 + j == 65536)
                        cout << "Seriously?" << endl;
                    return;
                } else if (!flag){
                    evaluator.multiply_plain(kCTs[j-1], plainInd, levelSum);
                    flag = true;
                } else {
                    Ciphertext tmp;
                    evaluator.multiply_plain(kCTs[j-1], plainInd, tmp);
                    evaluator.add_inplace(levelSum, tmp);
                }
            }
        }
        evaluator.mod_switch_to_inplace(levelSum, kToMCTs[i].parms_id()); // mod down the plaintext multiplication noise
        if(i == 0){
            evaluator.mod_switch_to_next_inplace(levelSum);
            ciphertext = levelSum;
        } else {
            evaluator.multiply_inplace(levelSum, kToMCTs[i - 1]);
            evaluator.relinearize_inplace(levelSum, relin_keys);
            evaluator.mod_switch_to_next_inplace(levelSum);
            evaluator.add_inplace(ciphertext, levelSum);
        }
    }

    vector<uint64_t> intInd(degree, 32769); // (p+1)/2
    Plaintext plainInd;
    Ciphertext tmep;
    batch_encoder.encode(intInd, plainInd);
    evaluator.multiply_plain(kToMCTs[255], plainInd, tmep);
    evaluator.mod_switch_to_next_inplace(tmep);
    evaluator.add_inplace(ciphertext, tmep);
}

// check in range
// if within [-range, range -1], returns 0, and returns random number in p o/w
void newRangeCheckPVW(vector<Ciphertext>& output, const int& range, const RelinKeys &relin_keys,\
                        const size_t& degree, const SEALContext& context, const PVWParam& param, const int upperbound = 64){ // we do one level of recursion, so no more than 4096 elements
    Evaluator evaluator(context);
    BatchEncoder batch_encoder(context);

    vector<Ciphertext> res(param.ell*2);

    for(int j = 0; j < param.ell; j++){
        cout << j << endl;
        vector<uint64_t> vectorOfInts(degree, 65537-range); 
        Plaintext plaintext;
        batch_encoder.encode(vectorOfInts, plaintext);
        auto tmp1 = output[j];
        evaluator.add_plain_inplace(tmp1, plaintext);
        lessThan_PatersonStockmeyer(res[j*2], tmp1, 65537, degree, relin_keys, context);

        cout << j << endl;
        vector<uint64_t> vectorOfInts2(degree, 65537-range); 
        Plaintext plaintext2;
        batch_encoder.encode(vectorOfInts2, plaintext2);
        auto tmp2 = output[j];
        evaluator.negate_inplace(tmp2);
        evaluator.add_plain_inplace(tmp2, plaintext2);
        lessThan_PatersonStockmeyer(res[j*2+1], tmp2, 65537, degree, relin_keys, context);
    }

    EvalMultMany_inpace(res, relin_keys, context);
    output = res;
}