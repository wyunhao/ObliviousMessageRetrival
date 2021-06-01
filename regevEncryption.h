#pragma once

#include "math/ternaryuniformgenerator.h"
#include "math/discreteuniformgenerator.h"
#include "math/discretegaussiangenerator.h"
#include <iostream>
using namespace std;
using namespace lbcrypto;

struct regevParam{
    int n;
    int q;
    int std_dev;
    int m;
    regevParam(){
        n = 500;
        q = 65537;
        std_dev = 1.6;
        m = 8100; // pk num, we take 8100 to guarantee 2^8100 >> 65537^512 ~ 2^(16*500)
    }
    regevParam(int n, int q, int std_dev, int m)
    : n(n), q(q), std_dev(std_dev), m(m)
    {}
};

typedef NativeVector regevSK;

struct regevCiphertext{
    NativeVector a;
    NativeInteger b;
};

typedef vector<regevCiphertext> regevPK;

regevSK regevGenerateSecretKey(const regevParam& param);
regevPK regevGeneratePublicKey(const regevParam& param, const regevSK& sk);
void regevEncSK(regevCiphertext& ct, const int& msg, const regevSK& sk, const regevParam& param, const bool& pk_gen = false);
void regevEncPK(regevCiphertext& ct, const int& msg, const regevPK& pk, const regevParam& param);
void regevDec(int& msg, const regevCiphertext& ct, const regevSK& sk, const regevParam& param);

/////////////////////////////////////////////////////////////////// Below are implementation

regevSK regevGenerateSecretKey(const regevParam& param){
    int n = param.n;
    int q = param.q;
    lbcrypto::TernaryUniformGeneratorImpl<regevSK> tug;
    return tug.GenerateVector(n, q);
}

void regevEncSK(regevCiphertext& ct, const int& msg, const regevSK& sk, const regevParam& param, const bool& pk_gen){
    NativeInteger q = param.q;
    int n = param.n;
    DiscreteUniformGeneratorImpl<NativeVector> dug;
    dug.SetModulus(q);
    ct.a = dug.GenerateVector(n);
    NativeInteger mu = q.ComputeMu();
    for (int i = 0; i < n; ++i) {
        ct.b += ct.a[i].ModMulFast(sk[i], q, mu);
    }
    ct.b.ModEq(q);
    if(!pk_gen)
        msg? ct.b.ModAddFastEq(3*q/4, q) : ct.b.ModAddFastEq(q/4, q);
    DiscreteGaussianGeneratorImpl<NativeVector> m_dgg(param.std_dev);
    ct.b.ModAddFastEq(m_dgg.GenerateInteger(q), q);
}

regevPK regevGeneratePublicKey(const regevParam& param, const regevSK& sk){
    regevPK pk(param.m);
    for(int i = 0; i < param.m; i++){
        regevEncSK(pk[i], 0, sk, param, true);
    }
    return pk;
}

void regevEncPK(regevCiphertext& ct, const int& msg, const regevPK& pk, const regevParam& param){
    NativeInteger q = param.q;
    ct.a = NativeVector(param.n);
    for(size_t i = 0; i < pk.size(); i++){
        if (rand()%2){
            for(int j = 0; j < param.n; j++){
                ct.a[j].ModAddFastEq(pk[i].a[j], q);
            }
            ct.b.ModAddFastEq(pk[i].b, q);
        }
    }
    msg? ct.b.ModAddFastEq(3*q/4, q) : ct.b.ModAddFastEq(q/4, q);
}

void regevDec(int& msg, const regevCiphertext& ct, const regevSK& sk, const regevParam& param){
    NativeInteger q = param.q;
    int n = param.n;
    NativeInteger inner(0);
    NativeInteger r = ct.b;
    NativeInteger mu = q.ComputeMu();
    for (int i = 0; i < n; ++i) {
        inner += ct.a[i].ModMulFast(sk[i], q, mu);
    }
    r.ModSubFastEq(inner, q);
    r.ModEq(q);

    cout << r << endl;
    msg = (r < q/2)? 0 : 1;
    //cout << msg << endl;
}