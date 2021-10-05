
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
        evaluator.mod_switch_to_next_inplace(output[i]); //XXX
    }
}

// take PVW sk's and output switching key, which is a ciphertext of size \ell*n, where n is the PVW ciphertext dimension
void genSwitchingKeyPVWPacked(vector<Ciphertext>& switchingKey, const SEALContext& context, const size_t& degree, 
                         const PublicKey& BFVpk, const SecretKey& BFVsk, const PVWsk& regSk, const PVWParam& params){ // TODOmulti: can be multithreaded easily
    
    // MemoryPoolHandle my_pool = MemoryPoolHandle::New(true);
    // auto old_prof = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool)));
    BatchEncoder batch_encoder(context);
    Encryptor encryptor(context, BFVpk);
    encryptor.set_secret_key(BFVsk);
    // switchingKey.resize(params.ell);

    int tempn = 1;
    for(tempn = 1; tempn < params.n; tempn *= 2){}
    for(int j = 0; j < params.ell; j++){
        vector<uint64_t> skInt(degree);
        for(size_t i = 0; i < degree; i++){
            // cout << i << endl;
            auto tempindex = i%uint64_t(tempn);
            if(int(tempindex) >= params.n)
            {
                skInt[i] = 0;
            } else {
                skInt[i] = uint64_t(regSk[j][tempindex].ConvertToInt() % 65537);
            }
        }
        // for(int i = 0; i < 120; i++)
        //     cout << skInt[i] <<' ';
        // cout << endl << endl;
        Plaintext plaintext;
        batch_encoder.encode(skInt, plaintext);
        encryptor.encrypt_symmetric(plaintext, switchingKey[j]);
    }
    // MemoryManager::SwitchProfile(std::move(old_prof));
}

// compute b - as using smaller key
void computeBplusASPVWOptimized(vector<Ciphertext>& output, \
        const vector<PVWCiphertext>& toPack, vector<Ciphertext>& switchingKey, const GaloisKeys& gal_keys,
        const SEALContext& context, const PVWParam& param){ // TODOmulti: can be multithreaded, not that easily, but doable
    MemoryPoolHandle my_pool = MemoryPoolHandle::New(true);
    auto old_prof = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool)));

    int tempn;
    for(tempn = 1; tempn < param.n; tempn*=2){}

    Evaluator evaluator(context);
    BatchEncoder batch_encoder(context);
    size_t slot_count = batch_encoder.slot_count();
    if(toPack.size() > slot_count){
        cerr << "Please pack at most " << slot_count << " PVW ciphertexts at one time." << endl;
        return;
    }
    // output.resize(param.ell);

    for(int i = 0; i < tempn; i++){
        vector<uint64_t> vectorOfInts(toPack.size());
        for(size_t j = 0; j < toPack.size(); j++){
            int the_index = (i+int(j))%tempn;
            if(the_index >= param.n)
            {
                vectorOfInts[j] = 0;
            } else {
                vectorOfInts[j] = uint64_t((toPack[j].a[the_index].ConvertToInt()));
            }
        }
        // if(i<10){
        //     for(int k = 0; k < 120; k++)
        //     cout << vectorOfInts[k] <<' ';
        // cout << endl<<endl;
        // }
        Plaintext plaintext;
        batch_encoder.encode(vectorOfInts, plaintext);
        
        for(int j = 0; j < param.ell; j++){
            if(i == 0){
                evaluator.multiply_plain(switchingKey[j], plaintext, output[j]); // times s[i]
            }
            else{
                Ciphertext temp;
                evaluator.multiply_plain(switchingKey[j], plaintext, temp);
                evaluator.add_inplace(output[j], temp);
            }
            evaluator.rotate_rows_inplace(switchingKey[j], 1, gal_keys);
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
        evaluator.mod_switch_to_next_inplace(output[i]); //XXX
    }
    MemoryManager::SwitchProfile(std::move(old_prof));
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
    // MemoryPoolHandle my_pool_larger = MemoryPoolHandle::New(true);
    // auto old_prof_larger = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool_larger)));
    vector<int> calculated(DegreeK, 0);
    Evaluator evaluator(context);
    // output.resize(DegreeK);
    output[0] = input;
    calculated[0] = 1; // degree 1, x
    Ciphertext res, base;
    vector<int> numMod(DegreeK, 0);

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
                            numMod[resdeg-1] = numMod[basedeg-1];

                            evaluator.mod_switch_to_inplace(res, base.parms_id()); // match modulus
                            evaluator.multiply_inplace(res, base);
                            evaluator.relinearize_inplace(res, relin_keys);
                            while(numMod[resdeg-1] < (ceil(log2(resdeg))/2)){
                                evaluator.mod_switch_to_next_inplace(res);
                                numMod[resdeg-1]+=1;
                            }
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
                        numMod[basedeg-1] = numMod[basedeg/2-1];
                        evaluator.square_inplace(base);
                        evaluator.relinearize_inplace(base, relin_keys);
                        while(numMod[basedeg-1] < (ceil(log2(basedeg))/2)){
                                evaluator.mod_switch_to_next_inplace(base);
                                numMod[basedeg-1]+=1;
                            }
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
    // MemoryManager::SwitchProfile(std::move(old_prof_larger));
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
    MemoryPoolHandle my_pool_larger = MemoryPoolHandle::New(true);
    auto old_prof_larger = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool_larger)));

    Evaluator evaluator(context);
    BatchEncoder batch_encoder(context);
    vector<Ciphertext> kCTs(256);
    // vector<shared_ptr<MemoryPoolHandle>> pools;
    vector<Ciphertext> temp;
    // util::MemoryPool* pool_ptr = new util::MemoryPool[256];
    // for(int i = 0; i < 256; i++){
    //     pools.push_back(make_shared<MemoryPoolHandle::New(true)>);
    //     temp.push_back(Ciphertext(pools[i]));
    // }
    // cout << "??? 1" << endl;
    // calUptoDegreeK(temp, input, 256, relin_keys, context);
    // cout << "??? 2" << endl;
    // for(size_t j = 0; j < temp.size()-1; j++){ // match to one level left, the one level left is for plaintext multiplication noise
    //     for(int i = 0; i < 7; i++){
    //         evaluator.mod_switch_to_next_inplace(temp[j]);
    //     }
    // }
    // for(int i = 255; i >= 0; i--){
    //     kCTs[i] = temp[i];
    //     temp[i].release();
    //     temp.resize(i);
    //     {
    //         auto pool = std::move(pools[i]);
    //         pools.pop_back();
    //     }
    // }
    {
        MemoryPoolHandle my_pool = MemoryPoolHandle::New(true);
        auto old_prof = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool)));
        vector<Ciphertext> temp(128);
        {
            MemoryPoolHandle my_pool2 = MemoryPoolHandle::New(true);
            // auto old_prof2 = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool2)));
            cout << "??? 1" << endl;
            for(int i = 0; i < 64; i++){
                temp.push_back(Ciphertext(my_pool2));
            }
            // temp.insert(temp.begin(), temp2.begin(), temp2.end());
            {
                cout << "???2" << endl;
                MemoryPoolHandle my_pool3 = MemoryPoolHandle::New(true);
                // auto old_prof3 = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool3)));
                //  cout << "???2" << endl;
                for(int i = 0; i < 64; i++){
                    temp.push_back(Ciphertext(my_pool3));
                }
                // {
                //     MemoryPoolHandle my_pool4 = MemoryPoolHandle::New(true);
                //     // auto old_prof4 = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool4)));
                //     cout << "???3" << endl;
                //     for(int i = 0; i < 32; i++){
                //         temp.push_back(Ciphertext(my_pool4));
                //     }
                //     {
                //         MemoryPoolHandle my_pool5 = MemoryPoolHandle::New(true);
                //         // auto old_prof5 = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool5)));
                //         cout << "???4" << endl;
                //         for(int i = 0; i < 32; i++){
                //             temp.push_back(Ciphertext(my_pool5));
                //         }
                //         cout << temp.size() << endl;
                        calUptoDegreeK(temp, input, 256, relin_keys, context);
                        cout << temp.size() << "---" << endl;
                        for(size_t j = 0; j < temp.size()-1; j++){ // match to one level left, the one level left is for plaintext multiplication noise
                            for(int i = 0; i < 3; i++){
                                evaluator.mod_switch_to_next_inplace(temp[j]);
                            }
                        }
                //         for(int i = 255; i > 255-32; i--){
                //             kCTs[i] = temp[i];
                //             temp[i].release();
                //         }
                //         // MemoryManager::SwitchProfile(std::move(old_prof5));
                //         cout << "???5" << endl;
                //     }
                //     for(int i = 255-32; i > 255-32-32; i--){
                //         kCTs[i] = temp[i];
                //         temp[i].release();
                //     }
                //     // MemoryManager::SwitchProfile(std::move(old_prof4));
                //     cout << "???6" << endl;
                // }
                // for(int i = 255-32-32; i > 255-32-32-32; i--){
                //     kCTs[i] = temp[i];
                //     temp[i].release();
                // }
                for(int i = 255; i > 255-32-32; i--){
                    kCTs[i] = temp[i];
                    temp[i].release();
                }
                // MemoryManager::SwitchProfile(std::move(old_prof3));
                cout << "???7" << endl;
            }
            for(int i = 255-32-32; i > 255-32-32-32-32; i--){
                kCTs[i] = temp[i];
                temp[i].release();
            }
            // for(int i = 255-32-32-32; i > 255-32-32-32-32; i--){
            //     kCTs[i] = temp[i];
            //     temp[i].release();
            // }
            // MemoryManager::SwitchProfile(std::move(old_prof2));
            cout << "???8" << endl;
        }
        for(int i = 0; i < 128; i++){
            kCTs[i] = temp[i];
            temp[i].release();
        }
        MemoryManager::SwitchProfile(std::move(old_prof));
    }
    vector<Ciphertext> kToMCTs(256);
    // std::chrono::seconds dura(90);
    // std::this_thread::sleep_for( dura );
    calUptoDegreeK(kToMCTs, kCTs[kCTs.size()-1], 256, relin_keys, context);
    
    cout << "2.1: ";
    for(size_t i = 0; i < kCTs[0].parms_id().size(); i++){
        cout << " " << kCTs[0].parms_id()[i];
    }
    cout  << endl;
    cout << "2.2: ";
    for(size_t i = 0; i < kToMCTs[0].parms_id().size(); i++){
        cout << " " << kToMCTs[0].parms_id()[i];
    }
    cout  << endl;
    // cout << "2.2: " << kToMCTs[0].parms_id() << endl;
    
    cout << "2.3: ";
    for(size_t i = 0; i < kCTs[0].parms_id().size(); i++){
        cout << " " << kCTs[0].parms_id()[i];
    }
    cout  << endl;
    // cout << "2.3: " << kCTs[0].parms_id() << endl;

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
            // evaluator.mod_switch_to_next_inplace(levelSum);
            ciphertext = levelSum;
        } else {
            evaluator.multiply_inplace(levelSum, kToMCTs[i - 1]);
            evaluator.relinearize_inplace(levelSum, relin_keys);
            // evaluator.mod_switch_to_next_inplace(levelSum);
            evaluator.add_inplace(ciphertext, levelSum);
        }
    }
    cout << "2.4: ";
    for(size_t i = 0; i < ciphertext.parms_id().size(); i++){
        cout << " " << ciphertext.parms_id()[i];
    }
    cout  << endl;
    // cout << "2.4: " << ciphertext.parms_id() << endl;

    vector<uint64_t> intInd(degree, 32769); // (p+1)/2
    Plaintext plainInd;
    Ciphertext tmep;
    batch_encoder.encode(intInd, plainInd);
    evaluator.multiply_plain(kToMCTs[255], plainInd, tmep);
    // evaluator.mod_switch_to_next_inplace(tmep);
    evaluator.add_inplace(ciphertext, tmep);
    cout << "2.5: ";
    for(size_t i = 0; i < ciphertext.parms_id().size(); i++){
        cout << " " << ciphertext.parms_id()[i];
    }
    cout  << endl;
    tmep.release();
    for(int i = 0; i < 256; i++){
        kCTs[i].release();
        kToMCTs[i].release();
    }
    // evaluator.release();
    // batch_encoder.release();
    MemoryManager::SwitchProfile(std::move(old_prof_larger));
    // cout << "2.5: " << ciphertext.parms_id() << endl;
}

// check in range
// if within [-range, range -1], returns 0, and returns random number in p o/w
void newRangeCheckPVW(vector<Ciphertext>& output, const int& range, const RelinKeys &relin_keys,\
                        const size_t& degree, const SEALContext& context, const PVWParam& param, const int upperbound = 64){ // we do one level of recursion, so no more than 4096 elements
    Evaluator evaluator(context);
    BatchEncoder batch_encoder(context);

    vector<Ciphertext> res(param.ell*2);

    for(int j = 0; j < param.ell; j++){
        {
            MemoryPoolHandle my_pool_larger = MemoryPoolHandle::New(true);
            auto old_prof_larger = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool_larger)));
            cout << j << endl;
            vector<uint64_t> vectorOfInts(degree, 65537-range); 
            Plaintext plaintext;
            batch_encoder.encode(vectorOfInts, plaintext);
            auto tmp1 = output[j];
            evaluator.add_plain_inplace(tmp1, plaintext);
            lessThan_PatersonStockmeyer(res[j*2], tmp1, 65537, degree, relin_keys, context);
            tmp1.release();
            plaintext.release();
        //     MemoryManager::SwitchProfile(std::move(old_prof_larger));
        // }

        // {   
        //     MemoryPoolHandle my_pool_larger = MemoryPoolHandle::New(true);
        //     auto old_prof_larger = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool_larger)));
            cout << j << endl;
            vector<uint64_t> vectorOfInts2(degree, 65537-range); 
            Plaintext plaintext2;
            batch_encoder.encode(vectorOfInts2, plaintext2);
            auto tmp2 = output[j];
            evaluator.negate_inplace(tmp2);
            evaluator.add_plain_inplace(tmp2, plaintext2);
            lessThan_PatersonStockmeyer(res[j*2+1], tmp2, 65537, degree, relin_keys, context);
            tmp2.release();
            plaintext2.release();
            MemoryManager::SwitchProfile(std::move(old_prof_larger));
        }
    }

    EvalMultMany_inpace(res, relin_keys, context);
    output = res;
}