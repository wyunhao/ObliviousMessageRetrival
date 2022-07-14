#pragma once

#include<iostream>
#include<fstream>
#include<string>
#include "regevEncryption.h"
#include "seal/seal.h"
#include <NTL/BasicThreadPool.h>
#include "global.h"
#include "client.h"
using namespace seal;

typedef vector<vector<uint64_t>> MREsharedSK;
typedef vector<vector<uint64_t>> MREsecretSK;

struct MREpk{
    vector<vector<uint64_t>> b_prime; // T x ell, double vector
    vector<MREsharedSK> shareSK; // T's ell x (ell * T + O(1)) double vectors

    MREpk() {}
    MREpk(vector<vector<uint64_t>>& b_prime, vector<MREsharedSK>& shareSK)
    : b_prime(b_prime), shareSK(shareSK)
    {}
};

struct MREgroupPK {
    vector<uint64_t> A;
    vector<uint64_t> b;

    MREgroupPK() {}
    MREgroupPK(vector<uint64_t>& A, vector<uint64_t>& b)
    : A(A), b(b)
    {}
};

struct MREsk{
    MREsecretSK secretSK; // ell x 450, double vector 
    MREsharedSK shareSK; // ell x (ell * T + O(1)), double vector

    MREsk() {}
    MREsk(MREsecretSK& secret, MREsharedSK& share)
    : secretSK(secret), shareSK(share)
    {}
};



vector<MREsk> MREgenerateSK(const PVWParam& param, const int partialSize = 40, const int partySize = 8) {
    vector<MREsk> mreSK(partySize);

    for (int i = 0; i < partySize; i++) {
        auto temp = PVWGenerateSecretKey(param);

        MREsecretSK leftSK(param.ell);
        MREsharedSK rightSK(param.ell);
        for (int l = 0; l < param.ell; l++) {
            leftSK[l].resize(param.n - partialSize);
            rightSK[l].resize(partialSize);

            int j = 0;
            for (; j < param.n - partialSize; j++) {
                leftSK[l][j] = temp[l][j].ConvertToInt();
            }
            for(; j < param.n; j++) {
                rightSK[l][j - param.n + partialSize] = temp[l][j].ConvertToInt();
            }
        }
        mreSK[i] = MREsk(leftSK, rightSK);
    }
    return mreSK;
}


vector<MREpk> MREgeneratePartialPK(const PVWParam& param, const vector<MREsk>& groupSK, const int crs, const int partialSize = 40) {

    vector<MREpk> pk(param.m);
    vector<uint64_t> A1(param.n - partialSize), b(param.ell);
    vector<vector<uint64_t>> b_prime(groupSK.size());
    vector<MREsharedSK> sharedSK(groupSK.size());

    for (int w = 0; w < param.m; w++) {
        srand(w);
        for (int i = 0; i < param.n - partialSize; i++) {
            A1[i] = rand() % param.q;
        }
        for (int i = 0; i < param.ell; i++) {
            b[i] = rand() % param.q;
        }

        // if (w == 0) {
        //     cout << w << ": " << A1 << endl << b << endl;
        // }

        for (int i = 0; i < groupSK.size(); i++) {
            b_prime[i].resize(param.ell);

            for (int l = 0; l < param.ell; l++) {
                auto temp = 0;
                for (int j = 0; j < param.n - partialSize; j++) {
                    temp = (temp + groupSK[i].secretSK[l][j] * A1[j]) % param.q;
                }
                b_prime[i][l] = (b[l] - temp) % param.q;
            }
        }

        for (int i = 0; i< groupSK.size(); i++) {
            sharedSK[i] = groupSK[i].shareSK;
        }

        pk[w] = MREpk(b_prime, sharedSK);
    }

    return pk;
}


vector<MREgroupPK> MREgeneratePK(const PVWParam& param, const vector<MREpk>& mrePK, const int crs, const int partySize = 8, const int partialSize = 40) {
    // srand(crs);

    vector<MREgroupPK> groupPK(param.m);

    for (int w = 0; w < param.m; w++) {
        vector<uint64_t> A(param.n), b(param.ell);
        vector<vector<int>> rhs(param.ell * partySize), lhs(param.ell * partySize);

        for (int i = 0; i < param.ell * partySize; i++) {
            rhs[i].resize(1);

            int party_ind = i / param.ell;
            int ell_ind = i % param.ell;
            rhs[i][0] = mrePK[w].b_prime[party_ind][ell_ind];
        }

        for (int i = 0; i < param.ell * partySize; i++) {
            lhs[i].resize(partialSize);

            for (int j = 0; j < partialSize; j++) {
                int party_ind = i / param.ell;
                int ell_ind = i % param.ell;

                lhs[i][j] = mrePK[w].shareSK[party_ind][ell_ind][j];
            }
        }

        vector<vector<long>> res = equationSolvingRandom(lhs, rhs, -1);
        srand(w);
        int i = 0;
        for (; i < param.n - partialSize; i++) {
            A[i] = rand() % param.q;
        }
        for (; i < param.n; i++) {
            A[i] = res[i - param.n + partialSize][0];
        }
        for (int i = 0; i < param.ell; i++) {
            b[i] = rand() % param.q;
        }
        // if (w == 0) {
        //     cout << w << ": " << A << endl << b << endl;
        // }
        groupPK[w] = MREgroupPK(A, b);
    }

    return groupPK;
}


void MREEncPK(PVWCiphertext& ct, const vector<int>& msg, const vector<MREgroupPK>& pk, const PVWParam& param) {
    NativeInteger q = param.q;
    ct.a = NativeVector(param.n);
    ct.b = NativeVector(param.ell);
    for(size_t i = 0; i < pk.size(); i++){
        if (rand()%2){
            for(int j = 0; j < param.n; j++){
                ct.a[j].ModAddFastEq(pk[i].A[j], q);
            }
            for(int j = 0; j < param.ell; j++){
                ct.b[j].ModAddFastEq(pk[i].b[j], q);
            }
        }
    }
    for(int j = 0; j < param.ell; j++){
        msg[j]? ct.b[j].ModAddFastEq(3*q/4, q) : ct.b[j].ModAddFastEq(q/4, q);
    }
}


void testMRE() {
    int partialSize = 40;
    auto param = PVWParam(450 + partialSize, 65537, 1.3, 16000, 4);
    int crs = 21;

    vector<MREsk> testSK = MREgenerateSK(param);
    vector<MREpk> testPK = MREgeneratePartialPK(param, testSK, crs);
    vector<MREgroupPK> groupPK = MREgeneratePK(param, testPK, crs);

    cout << "***************************************************************** " << endl;

    vector<vector<uint64_t>> result(testSK.size());

    cout << "expected b part : " << endl << groupPK[107].b << endl;
    // cout << "b prime: " << endl << testPK[0].b_prime << endl;

    for (int i=0; i<testSK.size(); i++) {
        result[i].resize(param.ell);
        
        for (int l=0; l<param.ell; l++) {
            auto temp = 0;
            for (int j=0; j<groupPK[0].A.size(); j++) {
                if (j < param.n - partialSize) {
                    temp = (temp + groupPK[107].A[j] * testSK[i].secretSK[l][j]) % param.q;
                } else {
                    temp = (temp + groupPK[107].A[j] * testSK[i].shareSK[l][j - param.n + partialSize]) % param.q;
                }
            }
            result[i][l] = temp;
        }
    }
    cout << endl <<  "result b part: " << endl << result << endl;

    // auto params = PVWParam(450 + 40, 65537, 1.3, 16000, 4); 
    // auto sk = PVWGenerateSecretKey(params);
    // auto pk = PVWGeneratePublicKey(params, sk);

    // cout << "check size: " << sk.size() << endl;

    // PVWCiphertext pktest = pk[0];
    // for (int i=0; i < sk.size(); i++) {
    //     cout << "**** " << i << " ****" << endl;
    //     int temp;
    //     for (int j=0; j<params.n; j++) {
    //         temp = (temp + sk[i][j].ConvertToInt() * pktest.a[j].ConvertToInt()) % params.q;
    //     }
    //     cout << temp << " ";
    //     cout << endl;

    //     for (int l = 0; l < params.ell; l++) {
    //         cout << pk[i].b[l].ConvertToInt() << " ";
    //     }
    //     cout << endl;
    // }
}
