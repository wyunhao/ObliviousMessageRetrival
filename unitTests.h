#pragma once

#include "regevToBFVSeal.h"
#include "examples_fromseal.h"
#include "retrieval.h"

void testMultMany1(){
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

void testrandomizedIndexRetrieval6(){
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
    vector<Ciphertext> SIC(100);
    for(int i = 0; i < 100; i++){
        encryptor.encrypt(plain_matrix, SIC[i]);
        if(i % 5 == 0)
            encryptor.encrypt(plain_matrix2, SIC[i]);
    }

    Ciphertext output;

    time_start = chrono::high_resolution_clock::now();
    size_t counter = 0;
    int seed = 1;
    randomizedIndexRetrieval(output, SIC, context, slot_count, counter, seed);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "Done [" << time_diff.count() << " microseconds]" << endl;
    cout << "    + Noise budget in result: " << decryptor.invariant_noise_budget(output) << " bits" << endl;
    cout << "    + Noise budget in result: " << decryptor.invariant_noise_budget(SIC[0]) << " bits" << endl;

    Plaintext plain_result;
    decryptor.decrypt(output, plain_result);
    batch_encoder.decode(plain_result, pod_matrix);
    print_matrix(pod_matrix, row_size);
    for(int i = 0; i < 65536/2; i++){
        if (pod_matrix[i] != 0){
            cout << pod_matrix[i] << " ";
        }
    }
    cout << endl;
}

void testPayloadRetrieval(){
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
