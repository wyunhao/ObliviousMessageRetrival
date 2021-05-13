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
