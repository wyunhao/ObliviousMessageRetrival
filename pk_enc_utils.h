#include "tfhe/tfhe.h"
#include <iostream>
#include <vector>
#include <string>
#include <time.h>
#include <cmath>
#include <algorithm>
#include <string>
using namespace std;

void genPkSingle(LweSample* result, double alpha, const LweKey* key){
    const int32_t n = key->params->n;
    result->b = 0;
    for (int32_t i = 0; i < n; ++i)
    {
        result->a[i] = uniformTorus32_distrib(generator);
        result->b += result->a[i]*key->key[i];
    }
    result->b = gaussian32(result->b, alpha); 

    result->current_variance = alpha*alpha;
}

void genPK(LweSample* result, double alpha, const LweKey* key, const TFheGateBootstrappingParameterSet *params, const int m = 500){
    // We have a security parameter m
    const LweParams *in_out_params = params->in_out_params;
    result = new_LweSample_array(m, in_out_params);
    for(int i = 0; i < m; i++){
        genPkSingle(result + i, alpha, key);
    }
}

void encryptAsymm(LweSample* result, const int msg, const LweSample* pk, const TFheGateBootstrappingParameterSet *params, const int subSetSize = 20, const int m = 500){
    int theN = params->in_out_params->n;
    int _theOnePlaintext = 536870912;
    int _theZeroPlaintext = -536870912;

    result = new_LweSample_array(1, params->in_out_params);
    for(int j = 0; j < theN; j++){
            result->a[j] = 0;
    }

    vector<int> subset;
    result->b = msg ? _theOnePlaintext : -_theZeroPlaintext;
    for(int i = 0; i < subSetSize; i++){
        int temp = rand()%m;
        while(count(subset.begin(), subset.end(), temp) != 0){
            temp = rand()%m;
        }
        subset.push_back(temp);
        
        for(int j = 0; j < theN; j++){
            result->a[j] += pk[temp].a[j];
        }
        result->b += pk[temp].b;
    }
}

// This main function includes all things that are in progress so very messy.
int main_in_progress(){
    uint32_t seed = time(NULL);
    srand(seed);
    tfhe_random_generator_setSeed(&seed, 1);
    const int32_t nb_samples = 1;
    const int32_t nb_trials = 200;

    // generate params 
    int32_t minimum_lambda = 100;
    TFheGateBootstrappingParameterSet *params = new_default_gate_bootstrapping_parameters(minimum_lambda);
    const LweParams *in_out_params = params->in_out_params;
    // generate the secret keyset
    TFheGateBootstrappingSecretKeySet *keyset = new_random_gate_bootstrapping_secret_keyset(params);
    int counter(0), counter2(0), count(0);
    int theN = params->in_out_params->n;
    double alpha = params->in_out_params->alpha_min;

    vector<int> allPoints(256);
    for(int i = 0; i < 256; i++){
        allPoints[i] = 	-2147483648 + 16777216*i;
        //cout << allPoints[i] << endl;
    }

    for (int32_t trial = 0; trial < nb_trials; ++trial) {
        if(count % 2000000 == 0)
            cout << count << endl;
        count++;
        // generate samples
        LweSample *test_in = new_LweSample_array(nb_samples, in_out_params);
        // generate inputs (64-->127)
        for (int32_t i = 0; i < nb_samples; ++i) {
            genPkSingle(test_in + i, alpha, keyset->lwe_key);
        }
        
        LweSample *test_out = new_LweSample_array(2, in_out_params);
        for(int j = 0; j < theN; j++){
                test_out->a[j] = 0;
        }
        test_out->b = allPoints[135] - 16777216/2;
        //if(rand()%2) test_out->b = 536870912;
        for(int i = 0; i < nb_samples; i++){
            for(int j = 0; j < theN; j++){
                test_out->a[j] += test_in[i].a[j];
            }
            test_out->b += test_in[i].b;
        }
        bootsSymEncrypt(test_out, 1, keyset);
        //bootsAND(test_out, test_out, test_out+1, &keyset->cloud);
        lweAddTo(test_out, test_out, in_out_params);
        bool mess1 = bootsSymDecrypt(test_out, keyset);
        Torus32 mu = lwePhase(test_out, keyset->lwe_key);

        long plain_modulus = 4294967296;
        double transferRatio = (double)plain_modulus/(double)4294967296;
        uint64_t resA = 0;
        for(int i = 0; i < theN; i++){
            if(keyset->lwe_key->key[i]){
                //resA = (resA + test_out->a[i]);
                resA = (resA + (long)((test_out->a[i] + 4294967296)*transferRatio));
                //resA += (long)((test_out->a[i] + 2147483648));
                resA %= plain_modulus;
            }
        }
        //uint32_t res = test_out->b;
        uint64_t res = (long)((test_out->b + 4294967296)*transferRatio) % 4294967296;
        //long res = test_out->b - resA;
        //long res = (long)((test_out->b + 2147483648)) - resA;
        //bool mess2 = (((resA + plain_modulus - res) % plain_modulus) > (allPoints[250]+2147483648+16777216/2));
        //bool mess3 = (((resA + plain_modulus - res) % plain_modulus) > (allPoints[136]+2147483648-16777216/2));
        cout << (mu+4294967296)%4294967296 << " " << (res - resA)%4294967296 << " " << allPoints[135] - 16777216/2<< endl;// << " " << allPoints[135]+2147483648 << " " <<  mess2 << " " << mess3 << endl;
        //if(trial < 20) cout << transferRatio << endl;
        //cout << mess2 << " " << mess1 << endl;
        

        //if(mess2) counter2 += 1;
        //if(mess1 != mess2) counter += 1;
        delete_LweSample_array(nb_samples, test_in);
        delete_LweSample_array(2, test_out);

    }
    cout << counter << " " << counter2 <<  endl;

    delete_gate_bootstrapping_secret_keyset(keyset);
    delete_gate_bootstrapping_parameters(params);

    return 0;
}
