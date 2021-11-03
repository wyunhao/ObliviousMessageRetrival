
#pragma once

#include "regevEncryption.h"
#include "seal/seal.h"
#include <NTL/BasicThreadPool.h>
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
        // cout << i << endl;
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
    Plaintext plaintext;
    vector<uint64_t> vectorOfInts(degree, 1);
    batch_encoder.encode(vectorOfInts, plaintext);
    evaluator.negate_inplace(output);
    evaluator.add_plain_inplace(output, plaintext);
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
    Plaintext plaintext;
    vector<uint64_t> vectorOfInts(degree, 1);
    batch_encoder.encode(vectorOfInts, plaintext);
    evaluator.negate_inplace(output);
    evaluator.add_plain_inplace(output, plaintext);
}

// innersum up to toCover amount, O(log(toCover)) time
void innerSum_inplace(Ciphertext& output, const GaloisKeys& gal_keys, const size_t& degree,
                const size_t& toCover, const SEALContext& context){
    Evaluator evaluator(context);
    for(size_t i = 1; i < toCover; i*=2){
        Ciphertext temp;
        if(i == degree/2)
        {
		//cout << "innerSum: " << 0 <<endl;
            evaluator.rotate_columns(output, gal_keys, temp);
            evaluator.add_inplace(output, temp);
        }
        else
        {
		//cout << "innerSum: " <<  degree/2 - i <<endl;
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

	chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;

    vector<uint64_t> pod_matrix(degree, 0ULL); // TODOmulti: move inside to do multi-threading.
    pod_matrix[0] = 1ULL;
    Plaintext plain_matrix;
    batch_encoder.encode(pod_matrix, plain_matrix);
    for(size_t i = 0; i < toExpandNum; i++){ // TODOmulti: change to do multi-threading.
        time_start = chrono::high_resolution_clock::now();
	if(i != 0){ // if not 0, need to rotate to place 0
            if(i == degree/2){
                evaluator.rotate_columns_inplace(toExpand, gal_keys);
            }
            else{
                evaluator.rotate_rows_inplace(toExpand, 1, gal_keys);
            }
        }
        evaluator.multiply_plain(toExpand, plain_matrix, expanded[i]);
	evaluator.mod_switch_to_next_inplace(expanded[i]);
	//evaluator.mod_switch_to_next_inplace(expanded[i]);

	time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        cout << "expandSIC: " << time_diff.count() << " " << i << "\n";

	time_start = chrono::high_resolution_clock::now();
        innerSum_inplace(expanded[i], gal_keys, degree, 32768, context); // This is to make future work less, and slowing by less than double for now.
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        cout << "expandSIC: " << time_diff.count() << " " << i << "\n\n";

	//innerSum_inplace(expanded[i], gal_keys, degree, 290, context); // 580 bytes, and each slot 2 bytes, so totally 290 slots. Can get up to 1KB
    }
}

// Takes one SIC compressed and expand then into SIC's each encrypt 0/1 in slots up to cover 580 bytes
void expandSICOptimized(vector<Ciphertext>& expanded, Ciphertext& toExpand, const GaloisKeys& gal_keys,
                const size_t& degree, const SEALContext& context, const size_t& toExpandNum){ // hardcoded for now
    BatchEncoder batch_encoder(context);
    Evaluator evaluator(context);
    expanded.push_back(toExpand);
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    
    Plaintext plain_matrix, plain_matrix2;
    Ciphertext tmp1_rot, tmp2_rot;


    for(size_t i = 2; i <= degree; i*=2){
        time_start = chrono::high_resolution_clock::now();
        cout << "expandSIC optimized: " << i << endl;
        vector<uint64_t> pod_matrix(degree, 0ULL);
        vector<uint64_t> pod_matrix2(degree, 1ULL);
        for(size_t j = 0; j < degree; j+=i){
            for(size_t k = 0; k < i/2; k++){
                pod_matrix[j + k] = 1;
                pod_matrix2[j + k] = 0;
            }
            

            //for(size_t k = 0; k < degree/i; k++){
            //    pod_matrix[j*degree/i + k] = 1;
            //    pod_matrix2[j*degree/i + k] = 0;
            //}
        }
        for(int i = 0; i < 32768; i++)
            cout << pod_matrix[i] << " ";
        cout << endl;
        for(int i = 0; i < 32768; i++)
            cout << pod_matrix2[i] << " ";
        cout << endl << endl;;
        batch_encoder.encode(pod_matrix, plain_matrix);
        batch_encoder.encode(pod_matrix2, plain_matrix2);

        auto cur_size = expanded.size();
        if(cur_size > toExpandNum)
            cur_size = toExpandNum;
        for(size_t j = 0; j < cur_size; j++){
            expanded.resize(expanded.size()+1);
            evaluator.multiply_plain(expanded[j], plain_matrix2, expanded[expanded.size()-1]);
            evaluator.multiply_plain_inplace(expanded[j], plain_matrix);
            if(i == degree){
                evaluator.rotate_columns(expanded[j], gal_keys, tmp1_rot);
                evaluator.rotate_columns(expanded[expanded.size()-1], gal_keys, tmp2_rot);
                evaluator.add_inplace(expanded[j], tmp1_rot);
                evaluator.add_inplace(expanded[expanded.size()-1], tmp2_rot);
            }
            else{
                evaluator.rotate_rows(expanded[j], (degree-i)/2, gal_keys, tmp1_rot);
                evaluator.rotate_rows(expanded[expanded.size()-1], i/2, gal_keys, tmp2_rot);
                evaluator.add_inplace(expanded[j], tmp1_rot);
                evaluator.add_inplace(expanded[expanded.size()-1], tmp2_rot);
            }
        }

        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        cout << time_diff.count() << " " << "\n";
    }
    expanded.resize(toExpandNum);
}

///////////////////////////////////////// MultiThreaded

inline // helper function
int getCurrentThread(int threadNum, int totalSize, int last){
    int interval = (totalSize/ threadNum);
    int dividor = 0;
    for(int i = threadNum; i > 0; i--){
        if(interval*i + (interval+1)*(threadNum-i) == totalSize)
            dividor = threadNum - i;
    }

    int indextst = 0;
    for(int index = 0; index < threadNum; index++){
        int first1;
        if(index < dividor){
            first1 = (interval+1)*index;
        }
        else{
            first1 = (interval+1)*dividor + interval*(index-dividor);
        }
        if(last == (totalSize - first1))
            indextst = index;
    }
    return indextst;
}

// takes a vector of ciphertexts, and mult them all together result in the first element of the vector
// depth optimal
inline
void EvalMultMany_inpaceMulti(vector<Ciphertext>& ciphertexts, const RelinKeys &relin_keys, const SEALContext& context){ // TODOmulti: can be multithreaded easily
    Evaluator evaluator(context);
    if(ciphertexts.size() == 0)
        return;
    while(ciphertexts.size() != 1){
        NTL_EXEC_RANGE(ciphertexts.size()/2, first, last);
        for(int i = first; i < last; i++){
            //if(i % 100 == 0)
            //    cout << "hello " << i << endl;
            evaluator.multiply_inplace(ciphertexts[i], ciphertexts[ciphertexts.size()/2+i]);
            evaluator.relinearize_inplace(ciphertexts[i], relin_keys);
            evaluator.mod_switch_to_next_inplace(ciphertexts[i]);
        }
        NTL_EXEC_RANGE_END;
        if(ciphertexts.size()%2 == 0)
            ciphertexts.resize(ciphertexts.size()/2);
        else{ // if odd, take the last one and mod down to make them compatible
            ciphertexts[ciphertexts.size()/2] = ciphertexts[ciphertexts.size()-1];
            evaluator.mod_switch_to_next_inplace(ciphertexts[ciphertexts.size()/2]);
            ciphertexts.resize(ciphertexts.size()/2+1);
        }
    }
}

// Multithreaded
// check in range
// if within [-range, range -1], returns 0, and returns random number in p o/w
void evalRangeCheckMemorySavingMulti(Ciphertext& output, const int& range, const RelinKeys &relin_keys,\
                        const size_t& degree, const SEALContext& context, const regevParam& param, const int upperbound = 64, const int threadNum = 8){ // we do one level of recursion, so no more than 4096 elements
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
        if(counter == 64){
            EvalMultMany_inpaceMulti(ciphertexts, relin_keys, context);
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
        if(counter == 64){
            EvalMultMany_inpaceMulti(ciphertexts, relin_keys, context);
            res[counter2++] = ciphertexts[0];
            counter = 0;
            ciphertexts.resize(0);
            ciphertexts.resize(upperbound);
        }
    }

    if(counter2 == 0){
        ciphertexts.resize(counter);
        EvalMultMany_inpaceMulti(ciphertexts, relin_keys, context);
        output = ciphertexts[0];
    } else {
        res.resize(counter2);
        EvalMultMany_inpaceMulti(res, relin_keys, context);
        output = res[0];
    }

    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    time_start = chrono::high_resolution_clock::now();
    booleanization(output, relin_keys, context);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << time_diff.count() << " " << "\n";

    Plaintext plaintext;
    vector<uint64_t> vectorOfInts(degree, 1);
    batch_encoder.encode(vectorOfInts, plaintext);
    evaluator.negate_inplace(output);
    evaluator.add_plain_inplace(output, plaintext);
}

// MultiThreaded
// Takes one SIC compressed and expand then into SIC's each encrypt 0/1 in slots up to cover 580 bytes
void expandSICMulti(vector<Ciphertext>& expanded, Ciphertext& toExpand, const GaloisKeys& gal_keys,
                const int& degree, const SEALContext& context, const size_t& toExpandNum, const int threadNum = 8){ 
    BatchEncoder batch_encoder(context);
    Evaluator evaluator(context);
    expanded.resize(toExpandNum);

    vector<uint64_t> pod_matrix(degree, 0ULL); // TODOmulti: move inside to do multi-threading.
    pod_matrix[0] = 1ULL;
    Plaintext plain_matrix;
    batch_encoder.encode(pod_matrix, plain_matrix);
    Ciphertext toExpandRotated;
    evaluator.rotate_columns(toExpand, gal_keys,toExpandRotated);

    NTL_EXEC_RANGE(toExpandNum, first, last);
    for(int i = first; i < last; i++){ // TODOmulti: change to do multi-threading.
        Ciphertext temp = toExpand;
        if(i != 0){ // if not 0, need to rotate to place 0
            if(i >= degree/2){
                temp = toExpandRotated;
            }
            if(i != degree/2){
                evaluator.rotate_rows_inplace(temp, i%(degree/2), gal_keys);
            }
        }
        //cout << i << endl;
        evaluator.multiply_plain(temp, plain_matrix, expanded[i]);
        //innerSum_inplace(expanded[i], gal_keys, degree, 32768, context); // This is to make future work less, and slowing by less than double for now.
        innerSum_inplace(expanded[i], gal_keys, degree, 290, context); // 580 bytes, and each slot 2 bytes, so totally 290 slots. Can get up to 1KB
    }
    NTL_EXEC_RANGE_END;
}

void computeBplusASMulti(Ciphertext& output, \
        const vector<regevCiphertext>& toPack, const vector<Ciphertext>& switchingKey,\
        const SEALContext& context, const regevParam& param, const int threadNum = 8){ // TODOmulti: can be multithreaded, not that easily, but doable


    Evaluator evaluator(context);
    BatchEncoder batch_encoder(context);
    size_t slot_count = batch_encoder.slot_count();
    if(toPack.size() > slot_count){
        cerr << "Please pack at most " << slot_count << " regev ciphertexts at one time." << endl;
        return;
    }
    vector<Ciphertext> tempvec(threadNum);

    //int interval = (param.n / threadNum);
    //int dividor = 0;
    //for(int i = threadNum; i > 0; i--){
    //    if(interval*i + (interval+1)*(threadNum-i) == param.n)
    //        dividor = threadNum - i;
    //}

    NTL_EXEC_RANGE(param.n, first, last);
    int indextst = getCurrentThread(threadNum, param.n, last);
    bool flag = false;
    for(int i = first; i < last; i++){
        //if (i % 100 == 0){
        //    cout << "computeBplusAS: " << i << endl;
        //}
        vector<uint64_t> vectorOfInts(toPack.size());
        for(size_t j = 0; j < toPack.size(); j++){
            vectorOfInts[j] = uint64_t((toPack[j].a[i].ConvertToInt())); // store at most degree amount of a[i]'s
        }
        Plaintext plaintext;
        batch_encoder.encode(vectorOfInts, plaintext);

        if(!flag){
            evaluator.multiply_plain(switchingKey[i], plaintext, tempvec[indextst]); // times s[i]
            flag = true;
        }
        else{
            Ciphertext temp;
            evaluator.multiply_plain(switchingKey[i], plaintext, temp);
            evaluator.add_inplace(tempvec[indextst], temp);
        }
    }
    NTL_EXEC_RANGE_END;

    for(int i = 0; i < threadNum; i++){
        if(i == 0)
            output = tempvec[i];
        else
            evaluator.add_inplace(output, tempvec[i]); // TODOmulti: addition can be performed in a tree shape
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
