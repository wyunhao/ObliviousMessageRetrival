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
        cout << cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder()/2 << endl;
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

void regevTest(){
    srand (time(NULL));
    auto params = regevParam(512, 65537, 15, 1024); // The secreet key, at least, is 130+ bits secure.
    auto sk = regevGenerateSecretKey(params);
    auto pk = regevGeneratePublicKey(params, sk);
    regevCiphertext ct; 
    int msg = rand()%2;
    int msg_dec;
    cout << msg << endl;
    regevEncPK(ct, msg, pk, params);
    regevDec(msg_dec, ct, sk, params);
    cout << msg_dec << endl;

    regevCiphertext ct2;
    regevEncSK(ct2, msg, sk, params);
    regevDec(msg_dec, ct2, sk, params);
    cout << msg_dec << endl;
}

void bfvRangeCheckTest(){
    usint plaintextModulus = 65537;
    double sigma = 3.2;
    SecurityLevel securityLevel = HEStd_NotSet;
    EncodingParams encodingParams(
      std::make_shared<EncodingParamsImpl>(plaintextModulus));
    CryptoContext<DCRTPoly> cryptoContext =
      CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
          encodingParams, securityLevel, sigma, 0, 30, 0, OPTIMIZED, 2, 0, 30, 65536/2);
    // enable features that you wish to use
    cryptoContext->Enable(ENCRYPTION);
    cryptoContext->Enable(SHE);
    LPKeyPair<DCRTPoly> keyPair = cryptoContext->KeyGen();  
    cryptoContext->EvalMultKeysGen(keyPair.secretKey);

    std::vector<int64_t> vectorOfInts1 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, -1, -2, -3,-4,-5,-6,0};
    Plaintext plaintext1 = cryptoContext->MakePackedPlaintext(vectorOfInts1);
    auto ct = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
    auto params = regevParam(512, 65537, 15, 1024);
    evalRangeCheck(ct, 5, cryptoContext, params);

    Plaintext plaintextDecMult;
    cryptoContext->Decrypt(keyPair.secretKey, ct, &plaintextDecMult);
    plaintextDecMult->SetLength(plaintext1->GetLength());
    cout << plaintextDecMult << endl;
}

void bfvFromRegevTest(){
    srand (time(NULL));
    auto params = regevParam(512, 65537, 15, 1024); 
    auto sk = regevGenerateSecretKey(params);
    auto pk = regevGeneratePublicKey(params, sk);

    int toPackNum = 10;
    vector<regevCiphertext> toPack(toPackNum);
    for(int i = 0; i < toPackNum; i++){
        int msg = rand()%2;
        regevEncPK(toPack[i], msg, pk, params);
        regevDec(msg, toPack[i], sk, params);
    }

    usint plaintextModulus = 65537;
    double sigma = 3.2;
    SecurityLevel securityLevel = HEStd_128_classic;
    EncodingParams encodingParams(
      std::make_shared<EncodingParamsImpl>(plaintextModulus));
    CryptoContext<DCRTPoly> cryptoContext =
      CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
          encodingParams, securityLevel, sigma, 0, 40, 0, OPTIMIZED, 2, 0, 30);
    // enable features that you wish to use
    cryptoContext->Enable(ENCRYPTION);
    cryptoContext->Enable(SHE);
    LPKeyPair<DCRTPoly> keyPair = cryptoContext->KeyGen();  
    cryptoContext->EvalMultKeysGen(keyPair.secretKey);

    vector<Ciphertext<DCRTPoly>> switchingKey(params.n);
    for(int i = 0; i < params.n; i++){
        vector<int64_t> skInt(cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder()/2, sk[i].ConvertToInt());
        auto temp_plain = cryptoContext->MakePackedPlaintext(skInt);
        switchingKey[i] = cryptoContext->Encrypt(keyPair.publicKey, temp_plain);
    }

    Ciphertext<DCRTPoly> ct;
    computeBplusAS(ct, toPack, switchingKey, cryptoContext, params);
    Plaintext plaintextDecMult;
    cryptoContext->Decrypt(keyPair.secretKey, ct, &plaintextDecMult);
    plaintextDecMult->SetLength(toPackNum);
    cout << plaintextDecMult << endl;
}

void testCoeffPacking(){
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 32768;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 35, \
                                                                            30, 30, 30, 30, 30, 30, 30, 30, 30, 30, \
                                                                            30, 30, 30, 30, 30, 30, 30, 30, 30, 30,\
                                                                            30, 30, 30, 30, 30, 30, 30, 30, 30, \
                                                                             30, 30, 35 }));

    parms.set_plain_modulus(65537);

    SEALContext context(parms, true, sec_level_type::none);
    print_parameters(context);
    cout << endl;
    auto qualifiers = context.first_context_data()->qualifiers();
    cout << "Batching enabled: " << boolalpha << qualifiers.using_batching << endl;

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

    size_t slot_count = batch_encoder.slot_count();
    size_t row_size = slot_count / 2;
    cout << "Plaintext matrix row size: " << row_size << endl;

    vector<uint64_t> pod_matrix(slot_count, 0ULL);

    cout << "Input plaintext matrix:" << endl;
    print_matrix(pod_matrix, row_size);

    /*
    First we use BatchEncoder to encode the matrix into a plaintext polynomial.
    */
    Plaintext plain_matrix(poly_modulus_degree);
    print_line(__LINE__);
    cout << "Encode plaintext matrix:" << endl;
    plain_matrix[0] = 0ULL;
    plain_matrix[1] = 1ULL;
    plain_matrix[2] = 2ULL;
    plain_matrix[3] = 3ULL;
    plain_matrix[row_size] = 4ULL;
    plain_matrix[row_size + 1] = 5ULL;
    plain_matrix[row_size + 2] = 6ULL;
    plain_matrix[row_size + 3] = 7ULL;
    //evaluator.transform_to_ntt_inplace(plain_matrix, parms.parms_id());

    /*
    We can instantly decode to verify correctness of the encoding. Note that no
    encryption or decryption has yet taken place.
    */
    vector<uint64_t> pod_result(poly_modulus_degree);
    cout << "    + Decode plaintext matrix ...... Correct." << endl;
    pod_result[0] = plain_matrix.data()[0];
    pod_result[1] = plain_matrix.data()[1];
    pod_result[2] = plain_matrix.data()[2];
    pod_result[3] = plain_matrix.data()[3];
    pod_result[row_size + 0] = plain_matrix.data()[row_size + 0];
    pod_result[row_size + 1] = plain_matrix.data()[row_size + 1];
    pod_result[row_size + 2] = plain_matrix.data()[row_size + 2];
    pod_result[row_size + 3] = plain_matrix.data()[row_size + 3];
    print_matrix(pod_result, row_size);

    /*
    Next we encrypt the encoded plaintext.
    */
    Ciphertext encrypted_matrix;
    print_line(__LINE__);
    cout << "Encrypt plain_matrix to encrypted_matrix." << endl;
    encryptor.encrypt(plain_matrix, encrypted_matrix);
    cout << "    + Noise budget in encrypted_matrix: " << decryptor.invariant_noise_budget(encrypted_matrix) << " bits"
         << endl;

    /*
    We now add the second (plaintext) matrix to the encrypted matrix, and square
    the sum.
    */
    print_line(__LINE__);
    cout << "Sum, square, and relinearize." << endl;
    //evaluator.add_plain_inplace(encrypted_matrix, plain_matrix2);
    // time_start = chrono::high_resolution_clock::now();
    
    Ciphertext result;
    time_start = chrono::high_resolution_clock::now();
    booleanization(encrypted_matrix,relin_keys,context);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Done [" << time_diff.count() << " microseconds]" << endl;
    cout << "    + Noise budget in result: " << decryptor.invariant_noise_budget(encrypted_matrix) << " bits" << endl;

    Plaintext plain_result;
    print_line(__LINE__);
    cout << "Decrypt and decode result." << endl;
    decryptor.decrypt(encrypted_matrix, plain_result);
    pod_result[0] = plain_result.data()[0];
    pod_result[1] = plain_result.data()[1];
    pod_result[2] = plain_result.data()[2];
    pod_result[3] = plain_result.data()[3];
    pod_result[row_size + 0] = plain_result.data()[row_size + 0];
    pod_result[row_size + 1] = plain_result.data()[row_size + 1];
    pod_result[row_size + 2] = plain_result.data()[row_size + 2];
    pod_result[row_size + 3] = plain_result.data()[row_size + 3];
    print_matrix(pod_result, row_size);
    cout << "    + Result plaintext matrix ...... Correct." << endl;
    batch_encoder.decode(plain_result, pod_result);
    print_matrix(pod_result, row_size);

}