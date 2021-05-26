#include "regevToBFV.h"


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
    SecurityLevel securityLevel = HEStd_128_classic;
    EncodingParams encodingParams(
      std::make_shared<EncodingParamsImpl>(plaintextModulus));
    CryptoContext<DCRTPoly> cryptoContext =
      CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
          encodingParams, securityLevel, sigma, 0, 20, 0, OPTIMIZED, 2);
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
    auto params = regevParam(512, 65537, 15, 1024); // The secreet key, at least, is 130+ bits secure.
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
          encodingParams, securityLevel, sigma, 0, 20, 0, OPTIMIZED, 2);
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

int main(){
    //regevTest();
    bfvFromRegevTest();
}