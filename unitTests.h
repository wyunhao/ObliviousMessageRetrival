#pragma once

#include "PVWToBFVSeal.h"
#include "examples_fromseal.h"
#include "retrieval.h"
#include <NTL/BasicThreadPool.h>
#include <NTL/ZZ.h>
#include "client.h"


void testMultMany1(){
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 32768;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 35, \
                                                                            30, 30, 30, 30, 30, 30, 30, 30, 30, 30, \
                                                                            30, 30, 30, 30, 30, 30, 30, 30, 30, 33,\
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
    pod_matrix[0] = 0ULL;
    pod_matrix[1] = 1ULL;
    pod_matrix[2] = 2ULL;
    pod_matrix[3] = 3ULL;
    pod_matrix[row_size] = 4ULL;
    pod_matrix[row_size + 1] = 5ULL;
    pod_matrix[row_size + 2] = 6ULL;
    pod_matrix[row_size + 3] = 7ULL;

    cout << "Input plaintext matrix:" << endl;
    print_matrix(pod_matrix, row_size);

    /*
    First we use BatchEncoder to encode the matrix into a plaintext polynomial.
    */
    Plaintext plain_matrix;
    print_line(__LINE__);
    cout << "Encode plaintext matrix:" << endl;
    batch_encoder.encode(pod_matrix, plain_matrix);

    /*
    We can instantly decode to verify correctness of the encoding. Note that no
    encryption or decryption has yet taken place.
    */
    vector<uint64_t> pod_result;
    cout << "    + Decode plaintext matrix ...... Correct." << endl;
    batch_encoder.decode(plain_matrix, pod_result);
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
    Operating on the ciphertext results in homomorphic operations being performed
    simultaneously in all 8192 slots (matrix elements). To illustrate this, we
    form another plaintext matrix

        [ 1,  2,  1,  2,  1,  2, ..., 2 ]
        [ 1,  2,  1,  2,  1,  2, ..., 2 ]

    and encode it into a plaintext.
    */
    vector<uint64_t> pod_matrix2;
    for (size_t i = 0; i < slot_count; i++)
    {
        pod_matrix2.push_back((i & size_t(0x1)) + 1);
    }
    Plaintext plain_matrix2;
    batch_encoder.encode(pod_matrix2, plain_matrix2);
    cout << endl;
    cout << "Second input plaintext matrix:" << endl;
    print_matrix(pod_matrix2, row_size);

    /*
    We now add the second (plaintext) matrix to the encrypted matrix, and square
    the sum.
    */
    print_line(__LINE__);
    cout << "Sum, square, and relinearize." << endl;
    //evaluator.add_plain_inplace(encrypted_matrix, plain_matrix2);
    // time_start = chrono::high_resolution_clock::now();

    vector<Ciphertext> ciphertexts(33);
    for(int i = 0; i < 33; i++){
        encryptor.encrypt(plain_matrix, ciphertexts[i]);
    }
    
    Ciphertext result;
    time_start = chrono::high_resolution_clock::now();
    evaluator.multiply_many(ciphertexts,relin_keys,result);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Done [" << time_diff.count() << " microseconds]" << endl;
    cout << "    + Noise budget in result: " << decryptor.invariant_noise_budget(result) << " bits" << endl;

    Plaintext plain_result;
    print_line(__LINE__);
    cout << "Decrypt and decode result." << endl;
    decryptor.decrypt(result, plain_result);
    batch_encoder.decode(plain_result, pod_result);
    cout << "    + Result plaintext matrix ...... Correct." << endl;
    print_matrix(pod_result, row_size);

    time_start = chrono::high_resolution_clock::now();
    EvalMultMany_inpace(ciphertexts, relin_keys, context);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Done [" << time_diff.count() << " microseconds]" << endl;
    cout << "    + Noise budget in result: " << decryptor.invariant_noise_budget(ciphertexts[0]) << " bits" << endl;

    print_line(__LINE__);
    cout << "Decrypt and decode result." << endl;
    decryptor.decrypt(ciphertexts[0], plain_result);
    batch_encoder.decode(plain_result, pod_result);
    cout << "    + Result plaintext matrix ...... Correct." << endl;
    print_matrix(pod_result, row_size);
}

void testExponentiation2(){
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
    pod_matrix[0] = 0ULL;
    pod_matrix[1] = 1ULL;
    pod_matrix[2] = 2ULL;
    pod_matrix[3] = 3ULL;
    pod_matrix[row_size] = 4ULL;
    pod_matrix[row_size + 1] = 5ULL;
    pod_matrix[row_size + 2] = 6ULL;
    pod_matrix[row_size + 3] = 7ULL;

    cout << "Input plaintext matrix:" << endl;
    print_matrix(pod_matrix, row_size);

    /*
    First we use BatchEncoder to encode the matrix into a plaintext polynomial.
    */
    Plaintext plain_matrix;
    print_line(__LINE__);
    cout << "Encode plaintext matrix:" << endl;
    batch_encoder.encode(pod_matrix, plain_matrix);

    /*
    We can instantly decode to verify correctness of the encoding. Note that no
    encryption or decryption has yet taken place.
    */
    vector<uint64_t> pod_result;
    cout << "    + Decode plaintext matrix ...... Correct." << endl;
    batch_encoder.decode(plain_matrix, pod_result);
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
    Operating on the ciphertext results in homomorphic operations being performed
    simultaneously in all 8192 slots (matrix elements). To illustrate this, we
    form another plaintext matrix

        [ 1,  2,  1,  2,  1,  2, ..., 2 ]
        [ 1,  2,  1,  2,  1,  2, ..., 2 ]

    and encode it into a plaintext.
    */
    vector<uint64_t> pod_matrix2;
    for (size_t i = 0; i < slot_count; i++)
    {
        pod_matrix2.push_back((i & size_t(0x1)) + 1);
    }
    Plaintext plain_matrix2;
    batch_encoder.encode(pod_matrix2, plain_matrix2);
    cout << endl;
    cout << "Second input plaintext matrix:" << endl;
    print_matrix(pod_matrix2, row_size);

    /*
    We now add the second (plaintext) matrix to the encrypted matrix, and square
    the sum.
    */
    print_line(__LINE__);
    cout << "Sum, square, and relinearize." << endl;
    //evaluator.add_plain_inplace(encrypted_matrix, plain_matrix2);
    // time_start = chrono::high_resolution_clock::now();

    vector<Ciphertext> ciphertexts(16);
    for(int i = 0; i < 16; i++){
        encryptor.encrypt(plain_matrix, ciphertexts[i]);
    }
    
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
    batch_encoder.decode(plain_result, pod_result);
    cout << "    + Result plaintext matrix ...... Correct." << endl;
    print_matrix(pod_result, row_size);

    time_start = chrono::high_resolution_clock::now();
    evaluator.exponentiate_inplace(ciphertexts[0], 33, relin_keys);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Done [" << time_diff.count() << " microseconds]" << endl;
    cout << "    + Noise budget in result: " << decryptor.invariant_noise_budget(ciphertexts[0]) << " bits" << endl;

    print_line(__LINE__);
    cout << "Decrypt and decode result." << endl;
    decryptor.decrypt(ciphertexts[0], plain_result);
    batch_encoder.decode(plain_result, pod_result);
    cout << "    + Result plaintext matrix ...... Correct." << endl;
    print_matrix(pod_result, row_size);
}

void testcomputeBplusAS3(){
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
    for(size_t i = 0; i < slot_count; i++){
        pod_matrix[i] = 2*i;
    }
    cout << "Input plaintext matrix:" << endl;
    print_matrix(pod_matrix, row_size);

    /*
    First we use BatchEncoder to encode the matrix into a plaintext polynomial.
    */
    Plaintext plain_matrix;
    print_line(__LINE__);
    cout << "Encode plaintext matrix:" << endl;
    batch_encoder.encode(pod_matrix, plain_matrix);

    /*
    We can instantly decode to verify correctness of the encoding. Note that no
    encryption or decryption has yet taken place.
    */
    vector<uint64_t> pod_result;
    cout << "    + Decode plaintext matrix ...... Correct." << endl;
    batch_encoder.decode(plain_matrix, pod_result);
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

    
    srand (time(NULL));
    auto params = regevParam(512, 65537, 1.6, 8100); 
    auto sk = regevGenerateSecretKey(params);
    auto pk = regevGeneratePublicKey(params, sk);

    int toPackNum = 100;
    vector<regevCiphertext> toPack(toPackNum);
    vector<int> msgs(toPackNum);
    for(int i = 0; i < toPackNum; i++){
        int msg = rand()%2;
        regevEncPK(toPack[i], msg, pk, params);
        regevDec(msgs[i], toPack[i], sk, params);
    }
    for(int i = 0; i < toPackNum; i++){
        cout << msgs[i] << " ";
    }
    cout << endl;

    time_start = chrono::high_resolution_clock::now();
    vector<Ciphertext> switchingKey;
    genSwitchingKey(switchingKey, context, poly_modulus_degree, public_key, sk, params);
    Ciphertext output;
    computeBplusAS(output, toPack, switchingKey, context, params);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Done [" << time_diff.count() << " microseconds]" << endl;
    cout << "    + Noise budget in result: " << decryptor.invariant_noise_budget(output) << " bits" << endl;

    time_start = chrono::high_resolution_clock::now();
    evalRangeCheck(output, 128, relin_keys, poly_modulus_degree, context, params);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Done [" << time_diff.count() << " microseconds]" << endl;
    cout << "    + Noise budget in result: " << decryptor.invariant_noise_budget(output) << " bits" << endl;

    Plaintext plain_result;
    print_line(__LINE__);
    cout << "Decrypt and decode result." << endl;
    decryptor.decrypt(output, plain_result);
    batch_encoder.decode(plain_result, pod_result);
    cout << "    + Result plaintext matrix ...... Correct." << endl;
    print_matrix(pod_result, row_size);
    for(int i = 0; i < 100; i++){
        cout << pod_result[i] << " ";
    }
    cout << endl;
}

void testSIC4(){
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 32768;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 35, \
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
    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);

    size_t slot_count = batch_encoder.slot_count();
    size_t row_size = slot_count / 2;
    cout << "Plaintext matrix row size: " << row_size << endl;

    vector<uint64_t> pod_matrix(slot_count, 0ULL);
    for(size_t i = 0; i < slot_count; i++){
        pod_matrix[i] = i;
    }
    cout << "Input plaintext matrix:" << endl;
    print_matrix(pod_matrix, row_size);

    /*
    First we use BatchEncoder to encode the matrix into a plaintext polynomial.
    */
    Plaintext plain_matrix;
    print_line(__LINE__);
    cout << "Encode plaintext matrix:" << endl;
    batch_encoder.encode(pod_matrix, plain_matrix);
    Ciphertext encrypted_matrix;
    encryptor.encrypt(plain_matrix, encrypted_matrix);

    vector<Ciphertext> tst;

    time_start = chrono::high_resolution_clock::now();
    expandSIC(tst, encrypted_matrix, galois_keys, slot_count, context, 7);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Done [" << time_diff.count() << " microseconds]" << endl;
    cout << "    + Noise budget in result: " << decryptor.invariant_noise_budget(tst[0]) << " bits" << endl;

    Plaintext plain_result;
    for(int i = 0; i < 7; i++){
        decryptor.decrypt(tst[i], plain_result);
        batch_encoder.decode(plain_result, pod_matrix);
        print_matrix(pod_matrix, row_size);
    }
}

void testdeterministIndexRetrieval5(){
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 32768;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 35, \
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
    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);

    size_t slot_count = batch_encoder.slot_count();
    size_t row_size = slot_count / 2;
    cout << "Plaintext matrix row size: " << row_size << endl;

    vector<uint64_t> pod_matrix(slot_count, 0ULL);
    for(size_t i = 0; i < slot_count; i++){
        pod_matrix[i] = 1;
    }
    cout << "Input plaintext matrix:" << endl;
    print_matrix(pod_matrix, row_size);

    /*
    First we use BatchEncoder to encode the matrix into a plaintext polynomial.
    */
    Plaintext plain_matrix, plain_matrix2;
    print_line(__LINE__);
    cout << "Encode plaintext matrix:" << endl;
    batch_encoder.encode(pod_matrix, plain_matrix);
    vector<uint64_t> pod_matrix2(slot_count, 0ULL);
    batch_encoder.encode(pod_matrix2, plain_matrix2);
    vector<Ciphertext> SIC(2000);
    for(int i = 0; i < 2000; i++){
        encryptor.encrypt(plain_matrix, SIC[i]);
        if(i % 5 == 0)
            encryptor.encrypt(plain_matrix2, SIC[i]);
    }

    Ciphertext output;

    time_start = chrono::high_resolution_clock::now();
    size_t counter = 0;
    deterministicIndexRetrieval(output, SIC, context, slot_count, counter);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Done [" << time_diff.count() << " microseconds]" << endl;
    cout << "    + Noise budget in result: " << decryptor.invariant_noise_budget(output) << " bits" << endl;
    cout << "    + Noise budget in result: " << decryptor.invariant_noise_budget(SIC[0]) << " bits" << endl;

    Plaintext plain_result;
    decryptor.decrypt(output, plain_result);
    batch_encoder.decode(plain_result, pod_matrix);
    print_matrix(pod_matrix, row_size);
}

// void testrandomizedIndexRetrieval6(){
//     chrono::high_resolution_clock::time_point time_start, time_end;
//     chrono::microseconds time_diff;
//     EncryptionParameters parms(scheme_type::bfv);
//     size_t poly_modulus_degree = 32768;
//     parms.set_poly_modulus_degree(poly_modulus_degree);
//     parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 35, 
//                                                                              30, 30, 35 }));

//     parms.set_plain_modulus(65537);

//     SEALContext context(parms, true, sec_level_type::none);
//     print_parameters(context);
//     cout << endl;
//     auto qualifiers = context.first_context_data()->qualifiers();
//     cout << "Batching enabled: " << boolalpha << qualifiers.using_batching << endl;

//     KeyGenerator keygen(context);
//     SecretKey secret_key = keygen.secret_key();
//     PublicKey public_key;
//     keygen.create_public_key(public_key);
//     RelinKeys relin_keys;
//     keygen.create_relin_keys(relin_keys);
//     Encryptor encryptor(context, public_key);
//     Evaluator evaluator(context);
//     Decryptor decryptor(context, secret_key);
//     BatchEncoder batch_encoder(context);
//     GaloisKeys galois_keys;
//     keygen.create_galois_keys(galois_keys);

//     size_t slot_count = batch_encoder.slot_count();
//     size_t row_size = slot_count / 2;
//     cout << "Plaintext matrix row size: " << row_size << endl;

//     vector<uint64_t> pod_matrix(slot_count, 0ULL);
//     for(size_t i = 0; i < slot_count; i++){
//         pod_matrix[i] = 1;
//     }
//     cout << "Input plaintext matrix:" << endl;
//     print_matrix(pod_matrix, row_size);

//     /*
//     First we use BatchEncoder to encode the matrix into a plaintext polynomial.
//     */
//     Plaintext plain_matrix, plain_matrix2;
//     print_line(__LINE__);
//     cout << "Encode plaintext matrix:" << endl;
//     batch_encoder.encode(pod_matrix, plain_matrix);
//     vector<uint64_t> pod_matrix2(slot_count, 0ULL);
//     batch_encoder.encode(pod_matrix2, plain_matrix2);
//     vector<Ciphertext> SIC(100);
//     for(int i = 0; i < 100; i++){
//         encryptor.encrypt(plain_matrix, SIC[i]);
//         if(i % 5 == 0)
//             encryptor.encrypt(plain_matrix2, SIC[i]);
//     }

//     Ciphertext output;

//     time_start = chrono::high_resolution_clock::now();
//     size_t counter = 0;
//     int seed = 1;
//     randomizedIndexRetrieval(output, SIC, context, slot_count, counter, seed);
//     time_end = chrono::high_resolution_clock::now();
//     time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
//     cout << "Done [" << time_diff.count() << " microseconds]" << endl;
//     cout << "    + Noise budget in result: " << decryptor.invariant_noise_budget(output) << " bits" << endl;
//     cout << "    + Noise budget in result: " << decryptor.invariant_noise_budget(SIC[0]) << " bits" << endl;

//     Plaintext plain_result;
//     decryptor.decrypt(output, plain_result);
//     batch_encoder.decode(plain_result, pod_matrix);
//     print_matrix(pod_matrix, row_size);
//     for(int i = 0; i < 65536/2; i++){
//         if (pod_matrix[i] != 0){
//             cout << pod_matrix[i] << " ";
//         }
//     }
//     cout << endl;
// }

void testPayloadRetrieval7(){
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 32768;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 35, \
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
    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);

    size_t slot_count = batch_encoder.slot_count();
    size_t row_size = slot_count / 2;
    cout << "Plaintext matrix row size: " << row_size << endl;

    vector<uint64_t> pod_matrix(slot_count, 0ULL);
    for(size_t i = 0; i < slot_count; i++){
        pod_matrix[i] = 1;
    }
    cout << "Input plaintext matrix:" << endl;
    print_matrix(pod_matrix, row_size);

    /*
    First we use BatchEncoder to encode the matrix into a plaintext polynomial.
    */
    Plaintext plain_matrix, plain_matrix2;
    print_line(__LINE__);
    cout << "Encode plaintext matrix:" << endl;
    batch_encoder.encode(pod_matrix, plain_matrix);
    vector<uint64_t> pod_matrix2(slot_count, 0ULL);
    batch_encoder.encode(pod_matrix2, plain_matrix2);
    int testsize = 10;
    vector<Ciphertext> SIC(testsize);
    for(int i = 0; i < testsize; i++){
        encryptor.encrypt(plain_matrix, SIC[i]);
        //if(i % 5 == 0)
        //    encryptor.encrypt(plain_matrix2, SIC[i]);
    }

    vector<vector<uint64_t>> payloads(testsize);
    for(int i = 0; i < testsize; i++){
        payloads[i].resize(slot_count, 0);
        for(int j = 0; j < 290; j++){
            payloads[i][j] = i+1;
        }
    }

    vector<Ciphertext> results(testsize);
    Ciphertext output;

    time_start = chrono::high_resolution_clock::now();
    int seed = 3;
    payloadRetrieval(results, payloads, SIC, context);
    vector<vector<int>> bipartite_map;
    bipartiteGraphGeneration(bipartite_map,testsize,64,3,seed);
    //for(int i = 0; i < testsize; i++){
    //    for(int j = 0; j < 10; j++){
    //        cout << bipartite_map[i][j] << endl;
    //    }
    //}
    payloadPacking(output, results, bipartite_map, slot_count, context, galois_keys);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Done [" << time_diff.count() << " microseconds]" << endl;
    cout << "    + Noise budget in result: " << decryptor.invariant_noise_budget(output) << " bits" << endl;
    cout << "    + Noise budget in result: " << decryptor.invariant_noise_budget(SIC[0]) << " bits" << endl;

    Plaintext plain_result;
    decryptor.decrypt(output, plain_result);
    batch_encoder.decode(plain_result, pod_matrix);
    print_matrix(pod_matrix, row_size);
    //int counter = 0;
    //for(int i = 0; i < 65536/2; i++){
    //    if (pod_matrix[i] != 0){
    //        cout << pod_matrix[i] << " ";
    //        counter++;
    //    }
    //}
    ////for(int i = 0; i < 3; i++){
    ////    for(int j = 0; j < 2; j++){
    ////        cout << bipartite_map[i][j] << endl;
    ////    }
    ////}
    //cout << endl << counter << endl;
}

void unitTestMultiCore(){
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 32768;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 35, \
                                                                            30, 30, 30, 30, 30, 30, 30, 30, 30, 30, \
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
    pod_matrix[0] = 0ULL;
    pod_matrix[1] = 1ULL;
    pod_matrix[2] = 2ULL;
    pod_matrix[3] = 3ULL;
    pod_matrix[row_size] = 4ULL;
    pod_matrix[row_size + 1] = 5ULL;
    pod_matrix[row_size + 2] = 6ULL;
    pod_matrix[row_size + 3] = 7ULL;

    cout << "Input plaintext matrix:" << endl;
    print_matrix(pod_matrix, row_size);

    /*
    First we use BatchEncoder to encode the matrix into a plaintext polynomial.
    */
    Plaintext plain_matrix;
    print_line(__LINE__);
    cout << "Encode plaintext matrix:" << endl;
    batch_encoder.encode(pod_matrix, plain_matrix);

    /*
    We can instantly decode to verify correctness of the encoding. Note that no
    encryption or decryption has yet taken place.
    */
    vector<uint64_t> pod_result;
    cout << "    + Decode plaintext matrix ...... Correct." << endl;
    batch_encoder.decode(plain_matrix, pod_result);
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
    Operating on the ciphertext results in homomorphic operations being performed
    simultaneously in all 8192 slots (matrix elements). To illustrate this, we
    form another plaintext matrix

        [ 1,  2,  1,  2,  1,  2, ..., 2 ]
        [ 1,  2,  1,  2,  1,  2, ..., 2 ]

    and encode it into a plaintext.
    */
    vector<uint64_t> pod_matrix2;
    for (size_t i = 0; i < slot_count; i++)
    {
        pod_matrix2.push_back((i & size_t(0x1)) + 1);
    }
    Plaintext plain_matrix2;
    batch_encoder.encode(pod_matrix2, plain_matrix2);
    cout << endl;
    cout << "Second input plaintext matrix:" << endl;
    print_matrix(pod_matrix2, row_size);

    /*
    We now add the second (plaintext) matrix to the encrypted matrix, and square
    the sum.
    */
    print_line(__LINE__);
    cout << "Sum, square, and relinearize." << endl;
    //evaluator.add_plain_inplace(encrypted_matrix, plain_matrix2);
    // time_start = chrono::high_resolution_clock::now();


    int testsize = 3;
    int threadsize = 16;

    vector<vector<Ciphertext>> ciphertexts(threadsize);
    for(int i = 0; i < threadsize; i++){
        ciphertexts[i].resize(testsize);
        for(int j = 0; j < testsize; j++)
            encryptor.encrypt(plain_matrix, ciphertexts[i][j]);
    }
    NTL::SetNumThreads(8);

    time_start = chrono::high_resolution_clock::now();

    NTL_EXEC_RANGE(threadsize, first, last);
    for(int i = first; i < last; i++){
        evaluator.square_inplace(ciphertexts[i][0]);
    }
    NTL_EXEC_RANGE_END;
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Done [" << time_diff.count() << " microseconds]" << endl;
    cout << "    + Noise budget in result: " << decryptor.invariant_noise_budget(ciphertexts[threadsize-1][0]) << " bits" << endl;

    Plaintext plain_result;
    print_line(__LINE__);
    cout << "Decrypt and decode result." << endl;
    decryptor.decrypt(ciphertexts[threadsize-1][0], plain_result);
    batch_encoder.decode(plain_result, pod_result);
    cout << "    + Result plaintext matrix ...... Correct." << endl;
    print_matrix(pod_result, row_size);
}

void testClientMatrixForming8(){
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 32768;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 35, \
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
    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);

    size_t slot_count = batch_encoder.slot_count();
    size_t row_size = slot_count / 2;
    cout << "Plaintext matrix row size: " << row_size << endl;

    vector<uint64_t> pod_matrix(slot_count, 0ULL);
    for(size_t i = 0; i < slot_count; i++){
        pod_matrix[i] = i;
    }
    cout << "Input plaintext matrix:" << endl;
    print_matrix(pod_matrix, row_size);

    /*
    First we use BatchEncoder to encode the matrix into a plaintext polynomial.
    */
    Plaintext plain_matrix, plain_matrix2;
    print_line(__LINE__);
    cout << "Encode plaintext matrix:" << endl;
    batch_encoder.encode(pod_matrix, plain_matrix);
    Ciphertext rhsEnc;
    encryptor.encrypt(plain_matrix, rhsEnc);

    int testsize = 100;
    pod_matrix = vector<uint64_t>(slot_count, 1ULL);
    batch_encoder.encode(pod_matrix, plain_matrix);
    vector<uint64_t> pod_matrix2(slot_count, 0ULL);
    batch_encoder.encode(pod_matrix2, plain_matrix2);
    vector<Ciphertext> SIC(testsize);
    for(int i = 0; i < testsize; i++){
        encryptor.encrypt(plain_matrix2, SIC[i]);
        if(i % 10 == 0)
            encryptor.encrypt(plain_matrix, SIC[i]);
    }

    Ciphertext indexPack;
    size_t counter = 0;
    deterministicIndexRetrieval(indexPack, SIC, context, slot_count, counter);


    time_start = chrono::high_resolution_clock::now();
    int seed = 3;
    int repeatition = 5;
    // Step 1, generate bipartite graph
    vector<vector<int>> bipartite_map;
    bipartiteGraphGeneration(bipartite_map,testsize,64,repeatition,seed);
    
    // Step 2, find pertinent indices
    map<int, int> pertinentIndices;
    decodeIndices(pertinentIndices, indexPack, testsize, slot_count, secret_key, context);

    // Step 3, form rhs
    vector<vector<int>> rhs;
    formRhs(rhs, rhsEnc, secret_key, slot_count, context);

    // Step 4, form lhs
    vector<vector<int>> lhs;
    formLhs(lhs, pertinentIndices, bipartite_map);

    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Done [" << time_diff.count() << " microseconds]" << endl;

    cout << "Expected: \n\tPertinent: ";
    for(int i = 0; i < testsize; i++){
        if(i % 10 == 0)
            cout << i << " ";
    }
    cout << endl << "\tPertient graphs: \n\t";
    counter = 0;
    for(int i = 0; i < testsize; i++){
        if(i % 10 == 0)
        {
            cout << counter++ << ": ";
            for(int j = 0; j < repeatition; j++){
                cout << bipartite_map[i][j] << " ";
            }
            cout << "\n\t";
        }
    }

    cout << "\n";

    cout << "What we get:\n\t";

    for(size_t i = 0; i < lhs.size(); i++){
        for(size_t j = 0; j < lhs[i].size(); j++){
            cout << lhs[i][j] << " ";
        }
        cout << "\n\t";
    }
    cout << endl;
    cout << rhs.size() << " " << rhs[0].size() << endl;
    for(size_t i = 0; i < 64; i++){
        cout << i << ": ";
        for(size_t j = 0; j < rhs[i].size(); j++){
            cout << rhs[i][j] << " ";
        }
        cout << endl;
    }
}

void testEquationSolving9(){
    //int payloadSize = 290;
    //int blockSize = 1;
    //int bucketNum = 4;
    vector<vector<int>> rhs = {
        {(1*1+3*3+527*527)%65537, (1*2+3*6+527*65536)%65537},
        {(2*1+32*3+35*527)%65537, (2*2+32*6+35*65536)%65537},
        {(5*1+21*3+643*527)%65537, (5*2+21*6+643*65536)%65537},
        {(21*1+45*3+231*527)%65537, (21*2+45*6+231*65536)%65537}
    };
    //int x1(1), x2(3), x3(527);

    //vector<vector<int>> lhs = {
    //    {1, 2, 2, 0, 2, 3, 8, 0},
    //    {2, 0, 3, 0, 2, 3, 8, 0},
    //    {3, 0, 2, 6, 2, 3, 8, 0},
    //    {4, 0, 2, 0, 23, 3, 8, 0},
    //    {5, 0, 2, 0, 2, 43, 8, 0},
    //    {6, 0, 2, 0, 2, 3, 67, 0},
    //    {7, 0, 2, 0, 2, 3, 8, 89},
    //    {8, 0, 2, 0, 2, 3, 8, 0},
    //    {8, 0, 2, 0, 2, 3, 8, 755},
    //    {8, 0, 2, 0, 2, 3, 123, 0},
    //};
    vector<vector<int>> lhs = {
        {1,3,527},
        {2,32,35},
        {5,21,643},
        {21,45,231}
    };
    auto newrhs = equationSolving(lhs, rhs, 2);
    for(size_t i = 0; i < lhs.size(); i++){
        for(size_t j = 0; j < lhs[i].size(); j++){
            cout << lhs[i][j] << " ";
        }
        cout << endl;
    }
    for(size_t i = 0; i < newrhs.size(); i++){
        cout << newrhs[i] << endl;;
    }

}

void testMomerySavingBPlusA10(){
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
    for(size_t i = 0; i < slot_count; i++){
        pod_matrix[i] = 2*i;
    }
    cout << "Input plaintext matrix:" << endl;
    print_matrix(pod_matrix, row_size);

    /*
    First we use BatchEncoder to encode the matrix into a plaintext polynomial.
    */
    Plaintext plain_matrix;
    print_line(__LINE__);
    cout << "Encode plaintext matrix:" << endl;
    batch_encoder.encode(pod_matrix, plain_matrix);

    /*
    We can instantly decode to verify correctness of the encoding. Note that no
    encryption or decryption has yet taken place.
    */
    vector<uint64_t> pod_result;
    cout << "    + Decode plaintext matrix ...... Correct." << endl;
    batch_encoder.decode(plain_matrix, pod_result);
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

    
    srand (time(NULL));
    auto params = regevParam(512, 65537, 1.6, 8100); 
    auto sk = regevGenerateSecretKey(params);
    auto pk = regevGeneratePublicKey(params, sk);

    int toPackNum = 100;
    vector<regevCiphertext> toPack(toPackNum);
    vector<int> msgs(toPackNum);
    for(int i = 0; i < toPackNum; i++){
        int msg = rand()%2;
        regevEncPK(toPack[i], msg, pk, params);
        regevDec(msgs[i], toPack[i], sk, params);
    }
    for(int i = 0; i < toPackNum; i++){
        cout << msgs[i] << " ";
    }
    cout << endl;

    time_start = chrono::high_resolution_clock::now();
    vector<Ciphertext> switchingKey;
    genSwitchingKey(switchingKey, context, poly_modulus_degree, public_key, sk, params);
    Ciphertext output;
    computeBplusAS(output, toPack, switchingKey, context, params);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Done [" << time_diff.count() << " microseconds]" << endl;
    cout << "    + Noise budget in result: " << decryptor.invariant_noise_budget(output) << " bits" << endl;

    time_start = chrono::high_resolution_clock::now();
    evalRangeCheckMemorySaving(output, 128, relin_keys, poly_modulus_degree, context, params);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Done [" << time_diff.count() << " microseconds]" << endl;
    cout << "    + Noise budget in result: " << decryptor.invariant_noise_budget(output) << " bits" << endl;

    Plaintext plain_result;
    print_line(__LINE__);
    cout << "Decrypt and decode result." << endl;
    decryptor.decrypt(output, plain_result);
    batch_encoder.decode(plain_result, pod_result);
    cout << "    + Result plaintext matrix ...... Correct." << endl;
    print_matrix(pod_result, row_size);
    for(int i = 0; i < 100; i++){
        cout << pod_result[i] << " ";
    }
    cout << endl;
}

void PVWtest(){
    PVWParam param;
    param.ell = 10;
    auto sk = PVWGenerateSecretKey(param);
    auto pk = PVWGeneratePublicKey(param, sk);

    srand(time(NULL));
    vector<int> msg(param.ell);
    for(int i = 0; i < param.ell; i++){
        msg[i] = rand()%2;
    }
    PVWCiphertext ct;
    PVWEncPK(ct, msg, pk, param);
    vector<int> out;
    PVWDec(out, ct, sk, param);

    for(int i = 0; i < param.ell; i++)
        cout << out[i] << " " << msg[i] << endl;
}

void degreeUpToTest(){
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 32768;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 35, \
                                                                            30, 30, 30, 30, 30, 30, 30, 30, 30, 30, \
                                                                            30, 30, 30, 30, 30, 30, 30, 30, 30, 30,\
                                                                            30, 30, 30, 30, 20, 30 }));

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
    for(size_t i = 0; i < slot_count; i++){
        pod_matrix[i] = i;
    }
    cout << "Input plaintext matrix:" << endl;
    print_matrix(pod_matrix, row_size);

    /*
    First we use BatchEncoder to encode the matrix into a plaintext polynomial.
    */
    Plaintext plain_matrix;
    print_line(__LINE__);
    cout << "Encode plaintext matrix:" << endl;
    batch_encoder.encode(pod_matrix, plain_matrix);

    Ciphertext encrypted_matrix;
    print_line(__LINE__);
    cout << "Encrypt plain_matrix to encrypted_matrix." << endl;
    encryptor.encrypt(plain_matrix, encrypted_matrix);

    time_start = chrono::high_resolution_clock::now();

    vector<Ciphertext> output, output2;
    cout << "    + Noise budget in result: " << decryptor.invariant_noise_budget(encrypted_matrix) << " bits" << endl;
    // evaluator.mod_switch_to_next_inplace(encrypted_matrix);
    // evaluator.mod_switch_to_next_inplace(encrypted_matrix);
    // cout << "    + Noise budget in result: " << decryptor.invariant_noise_budget(encrypted_matrix) << " bits" << endl;

    calUptoDegreeK(output, encrypted_matrix, 64, relin_keys, context);
    // calUptoDegreeK(output2, output[output.size()-1], 256, relin_keys, context);

    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Done [" << time_diff.count() << " microseconds]" << endl;
    cout << output.size() << endl;
    // cout << output2.size() << endl;

    for(size_t i = 0; i < 64; i++){
        Plaintext plain_result;
        print_line(__LINE__);
        cout << "Decrypt and decode result." << endl;
        decryptor.decrypt(output[i], plain_result);
        batch_encoder.decode(plain_result, pod_matrix);
        cout << "    + Result plaintext matrix ...... Correct." << endl;
        cout << "    + Noise budget in result: " << decryptor.invariant_noise_budget(output[i]) << " bits" << endl;
        // print_matrix(pod_matrix, row_size);
        for(int j = 0; j < 10; j++){
            cout << pod_matrix[j] << " ";
        }
        cout << endl;
    }
    // for(size_t i = 250; i < 256; i++){
    //     Plaintext plain_result;
    //     print_line(__LINE__);
    //     cout << "Decrypt and decode result." << endl;
    //     decryptor.decrypt(output2[i], plain_result);
    //     batch_encoder.decode(plain_result, pod_matrix);
    //     cout << "    + Result plaintext matrix ...... Correct." << endl;
    //     cout << "    + Noise budget in result: " << decryptor.invariant_noise_budget(output2[i]) << " bits" << endl;
    //     // print_matrix(pod_matrix, row_size);
    //     for(int j = 0; j < 10; j++){
    //         cout << pod_matrix[j] << " ";
    //     }
    //     cout << endl;
    // }
}

void testCalIndices(){
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;

    time_start = chrono::high_resolution_clock::now();

    vector<uint64_t> ind;
    calIndices(ind, 8009);

    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Done [" << time_diff.count() << " microseconds]" << endl;

    for(uint64_t i = 0; i < ind.size(); i++){
        cout << ind[i] << ", ";
    }
    cout << endl;
}

void LTtest(){
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 32768;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 35, \
                                                                            30, 30, 30, 30, 30, 30, 30, 30, 30, 30, \
                                                                            30, 30, 30, 30, 30, 30, 30, 30, 30, 30,\
                                                                            30, 30, 30, 30, 30, 35 }));

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
    for(size_t i = 0; i < slot_count; i++){
        pod_matrix[i] = 2*i;
    }
    cout << "Input plaintext matrix:" << endl;
    print_matrix(pod_matrix, row_size);

    /*
    First we use BatchEncoder to encode the matrix into a plaintext polynomial.
    */
    Plaintext plain_matrix;
    print_line(__LINE__);
    cout << "Encode plaintext matrix:" << endl;
    batch_encoder.encode(pod_matrix, plain_matrix);

    Ciphertext encrypted_matrix;
    print_line(__LINE__);
    cout << "Encrypt plain_matrix to encrypted_matrix." << endl;
    encryptor.encrypt(plain_matrix, encrypted_matrix);

    time_start = chrono::high_resolution_clock::now();

    Ciphertext output;
    lessThan_PatersonStockmeyer(output, encrypted_matrix, 65537, poly_modulus_degree, relin_keys, context);

    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Done [" << time_diff.count() << " microseconds]" << endl;

    Plaintext plain_result;
    print_line(__LINE__);
    cout << "Decrypt and decode result." << endl;
    decryptor.decrypt(output, plain_result);
    batch_encoder.decode(plain_result, pod_matrix);
    cout << "    + Result plaintext matrix ...... Correct." << endl;
    cout << "    + Noise budget in result: " << decryptor.invariant_noise_budget(output) << " bits" << endl;
    print_matrix(pod_matrix, row_size);
    for(int j = 0; j < 10; j++){
        cout << pod_matrix[j] << " ";
    }
    cout << endl;
    
}

void speedTest(int numcores = 4){
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    int totalNum = 1<<30;
    vector<int> total(totalNum, 2);
    NTL::SetNumThreads(numcores);
    time_start = chrono::high_resolution_clock::now();
    NTL_EXEC_RANGE(totalNum, first, last);
    for(int i = first; i < last; i++){
        total[i] *= 65537;
        total[i] *= 65537;
        total[i] %= 65535;
    }
    NTL_EXEC_RANGE_END;
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << time_diff.count() << " us for " << numcores << " core(s)." << endl;
}