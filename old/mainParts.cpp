#include "tfhe/tfhe.h"
#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <string>
#include "utils.h"
using namespace std;
using namespace seal;

//////////////////////////////////////////////////////
// From here potential library API's
// The key vector should be public keys. For now we use symmetric keys given that's the only thing we have
void OMD_Flag(LweSample *flag_x, int log_invFPR, int partyIndex, const vector<TFheGateBootstrappingSecretKeySet*>& keysForAll){
    for(int i = 0; i < log_invFPR; i++){
        bootsSymEncrypt(flag_x+i, 1, keysForAll[partyIndex]);
    }
    return;
}

void OMD_Detect(const LweSample *flag_x, const int log_invFPR, const TFheGateBootstrappingCloudKeySet *bk, const LweParams * in_out_params, LweSample* output){
    // assume output has at least length 1, and flag_x has length n
    // we also assume length >= 3
    LweSample *temp = new_LweSample_array(log_invFPR, in_out_params);
    for(int i = 0; i < log_invFPR; i++){
        bootsAND(temp+i, flag_x+i, flag_x+i, bk);
    }
    bootsAND(output, temp+0, temp+1, bk);
    for(int i = 2; i < log_invFPR; i++){
        bootsAND(output, output, temp+i, bk);
    }
    delete_LweSample_array(log_invFPR, temp);
    return;
}

//////////////////////////////////////////////////////
// From here (probably) potential library API's

void encryptTFHEKey(const TFheGateBootstrappingSecretKeySet* sk, const SEALContext& context, const PublicKey& public_key, const int& n, vector<Ciphertext>& bfv_enc_s){
    Encryptor encryptor(context, public_key);
    BatchEncoder encoder(context);

    bfv_enc_s.resize(n);
    vector<uint64_t> input(context.key_context_data()->parms().poly_modulus_degree(),1);
    Plaintext plain;
    encoder.encode(input, plain);
    for(int i = 0; i < n; i++){
        if(sk->lwe_key->key[i])
            encryptor.encrypt(plain, bfv_enc_s[i]);
        else
            encryptor.encrypt_zero(bfv_enc_s[i]);
    }
    return;
}

void fromTFHEtoBFV(const vector<LweSample*> tfhe_input, const vector<Ciphertext>& bfv_enc_s, const SEALContext& context, const int& n, const int& payloadSize, Ciphertext& ret){
    // tfhe_input has size payloadSize, and n is determined by security parameter, bfv_enc_s has size n

    BatchEncoder encoder(context);
    Evaluator evaluator(context);

    for(int i = 0; i < n; i++){
        vector<uint64_t> input(payloadSize);
        for(int j = 0; j < payloadSize; j++){
            input[j] = (tfhe_input[j]->a[i] + 2147483648);
        }
        Plaintext plain;
        encoder.encode(input, plain);
        Ciphertext temp;
        evaluator.multiply_plain(bfv_enc_s[i], plain, temp);
        evaluator.add_inplace(ret, temp);
    }
    vector<uint64_t> input(payloadSize);
    for(int j = 0; j < payloadSize; j++){
        input[j] = (2147483648*2 - tfhe_input[j]->b);
    }
    Plaintext plain;
    encoder.encode(input, plain);
    evaluator.add_plain_inplace(ret, plain);
    return;
}

void bfvDecoding(const Ciphertext& toDecode, const SEALContext& context, const SecretKey& secret_key, const int& payloadSize, vector<bool>& result){
    BatchEncoder encoder(context);
    Decryptor decryptor(context, secret_key);

    Plaintext plain;
    decryptor.decrypt(toDecode, plain);
    vector<uint64_t> temp;
    encoder.decode(plain, temp);
    result.resize(payloadSize);
    for(int i = 0; i < payloadSize; i++){
        result[i] = (((temp[i]) % (2147483648*2)) > 2147483648);
    }
    return;
}

//////////////////////////////////////////////
//From here main utils
// We first assume no new party joining. 
void InitializeKeys(TFheGateBootstrappingParameterSet* params, vector<TFheGateBootstrappingSecretKeySet*>& keysForAll, int numOfParties){
    const LweParams *in_out_params = params->in_out_params;

    // generate keys
    for(int i = 0; i < numOfParties; i++)
        keysForAll.push_back(new_random_gate_bootstrapping_secret_keyset(params));
    
    return;
}

void initializeFlagsForAlltransactions(TFheGateBootstrappingParameterSet *params, vector<TFheGateBootstrappingSecretKeySet*>& keysForAll, int numOfParties, int numOfTransactions, int log_invFPR, vector<LweSample*>& allTransactions){
    //int32_t minimum_lambda = 100;
    //TFheGateBootstrappingParameterSet *params = new_default_gate_bootstrapping_parameters(minimum_lambda);
    const LweParams *in_out_params = params->in_out_params;

    InitializeKeys(params, keysForAll, numOfParties);

    int partyCounter = 0;
    allTransactions.resize(numOfTransactions);
    for(int i = 0; i < numOfTransactions; i++){
        allTransactions[i] = new_LweSample_array(log_invFPR, in_out_params);
        OMD_Flag(allTransactions[i], log_invFPR, partyCounter++, keysForAll);
        partyCounter %= numOfParties;
    }
    return;
}

void detectForAllTransactions(TFheGateBootstrappingParameterSet *params, const TFheGateBootstrappingSecretKeySet* theKey, const vector<LweSample*>& allTransactions, vector<LweSample*>& SIC, int log_invFPR){
    SIC.resize(allTransactions.size());
    const LweParams *in_out_params = params->in_out_params;

    for(int i = 0; i < allTransactions.size(); i++){
        SIC[i] = new_LweSample_array(1, in_out_params);
        OMD_Detect(allTransactions[i], log_invFPR, &theKey->cloud, in_out_params, SIC[i]);
    }
    return;
}

//////////////////////////////////////////////
// Basically definitely be in the library

void linearEquationsSolver(vector<vector<uint64_t>> equations, vector<uint64_t>& res){
    // We assume equations to be size [n][n+1], where n is the number of variables to get
    // We assume all the equations are linear independent, and the n+1^th column is the rhs of the equation
    // We also assume the equation coeffs to be within 0~2^64, and res to be as well

    uint64_t n = equations.size(); res.resize(n);
    uint64_t i,j,k,b; // declare variables and matrixes as
    for(j=1; j<=n; j++) {
      for(i=1; i<=n; i++) {
         if(i!=j) {
            b=equations[i][j]/equations[j][j];
            for(k=1; k<=n+1; k++) { 
               equations[i][k]=equations[i][k]-b*equations[j][k];
            }
         }
      }
   }
   for(i=1; i<=n; i++) {
      res[i]=equations[i][n+1]/equations[i][i];
   }
   return;
}

//template <typename T>
//void formLinearEquationsNotNormalized(const vector<T>& weightsInSlots, const vector<T>& amountInSlots, T rhs, vector<T>& equation){
//    // here we assume no collision. If we have collision
//    equation.resize(amountInSlots.size());
//    for(int i = 0; i < amountInSlots.size(); i++){
//        if(amountInSlots[i] == 1)
//            equation[i] = weightsInSlots[i];
//        else if(amountInSlots[i] == 0)
//            continue;
//        else{
//            cerr << "Something wrong happen! There are " << amountInSlots[i] << " transactions in this slot!" << endl;
//            exit(1);
//        }
//    }
//}

template <typename T>
void normalizeEquations(const vector<EachBucket>& allBuckets, const vector<int>& pertinentCollection, const vector<int>& rhs, const vector<vector<EachTransaction>>& TransactionsAllCopies, vector<vector<T>> equationsNormalized){
    // allBuckets has size m, pertinentCollection has size n and hamming weight k, rhs has size m
    equationsNormalized.resize(m);
    for(int i = 0; i < m; i++) {equationsNormalized[i].resize(k + 1, 0); equationsNormalized[i][k] = rhs[i];} // +1 is for rhs and assign it
    int varCount = 0;
    for(int i = 0; i < n; i++){
        if(pertinentCollection[i]){
            for(int j = 0; j < c; j++){
                auto tempTrans = &TransactionsAllCopies[j][i];
                equationsNormalized[tempTrans->ithTransaction][varCount] = tempTrans->weight;
            }
            varCount += 1;
            if(varCount > k){
                cerr << "Something Went wrong. Here in TFHE_BFV_TST.CPP line 193" << endl;
            }
        }
    }
}

//////////////////////////////////////////////
// Unit Tests

void testOMDandTFHEtoBFV(){
    int32_t minimum_lambda = 100;
    TFheGateBootstrappingParameterSet *params = new_default_gate_bootstrapping_parameters(minimum_lambda);
    vector<TFheGateBootstrappingSecretKeySet*> keysForAll;
    vector<LweSample*> allTransactions;
    vector<LweSample*> SIC;
    int log_inv_fpr = 10;
    int numOfParties = 10;
    int numOfTransactions = 20;

    // OMD.flag and OMD.detect
    initializeFlagsForAlltransactions(params, keysForAll, numOfParties, numOfTransactions, log_inv_fpr, allTransactions);
    detectForAllTransactions(params, keysForAll[1], allTransactions, SIC, log_inv_fpr);
    for(int i = 0; i < SIC.size(); i++){
        cout << bootsSymDecrypt(SIC[i], keysForAll[1]) << " ";
    }
    cout << endl;

    // Initialize BFV params
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 50,50,50,50 }));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 43));
    //uint64_t plainmodulus = parms.plain_modulus().value();
    SEALContext context(parms);
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    int theN = params->in_out_params->n;

    vector<Ciphertext> bfv_enc_s;
    encryptTFHEKey(keysForAll[1], context, public_key, theN, bfv_enc_s);

    Ciphertext ret(context);
    fromTFHEtoBFV(SIC, bfv_enc_s, context, theN, numOfTransactions, ret);

    vector<bool> theDecodedRes;
    bfvDecoding(ret, context, secret_key, numOfTransactions, theDecodedRes);
    for(int i = 0; i < theDecodedRes.size(); i++){
        if(theDecodedRes[i])
            cout << 1 << " ";
        else
            cout << 0 << " ";
    }
    cout << endl;

    // Deleting
    delete_gate_bootstrapping_parameters(params);
    for(int i = 0; i < numOfParties; i++){
        delete_gate_bootstrapping_secret_keyset(keysForAll[i]);
    }
    for(int i = 0; i < numOfTransactions; i++){
        delete_LweSample_array(log_inv_fpr, allTransactions[i]);
        delete_LweSample_array(1, SIC[i]);
    }

    return;
}

int main(){
    testOMDandTFHEtoBFV();
}

// NOTES:
//  What already done:
//      1. TFHE to BFV, and BFV decoding (tested)
//      2. Unit Proporgation & Self-resolving & Find what are the pertinent transactions (tested)
//      3. Form equations (to test)
//  What to do next:
//      1. Linear equation solver: find some library
//      2. Get weight sum using Add circuit & get rhs/payload using Add circuit & get how many are in the same slot
//          2.i: First assign weight, transform into bit representation
//          2.ii: Encrypt each bit, and multiply by SIC
//          2.iii: Add to slot using circuit. (So the slots container should be like vector<*LweSample>, with size N, and LweSample inside has bitlength say 16)
//      3. Integration tests
