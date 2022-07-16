#pragma once

#include <iostream>
#include <fstream>
#include <string>
#include <random>
#include "regevEncryption.h"
#include "seal/seal.h"
#include "global.h"
#include "client.h"


using namespace seal;

typedef mt19937 RNG;
RNG rng; // keep one global instance (per thread)

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

// extension of MREgroupPK, used to verify the correctness of A, b in groupPK
// notice that all data exposed can be shared and public, no secrecy harmed
struct MREPublicKey {
    vector<MREgroupPK> groupPK; // size of param.m 
    vector<MREpk> recipientPK; // size of param.m

    MREPublicKey() {}
    MREPublicKey(vector<MREgroupPK>& groupPK, vector<MREpk>& recipientPK)
    : groupPK(groupPK), recipientPK(recipientPK)
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

    rng.seed(crs);
    std::uniform_int_distribution<std::mt19937::result_type> dist(0, 65536); // distribution in range q

    for (int w = 0; w < param.m; w++) {
        for (int i = 0; i < param.n - partialSize; i++) {
            A1[i] = dist(rng) % param.q;
        }
        for (int i = 0; i < param.ell; i++) {
            b[i] = dist(rng) % param.q;
        }

        for (int i = 0; i < groupSK.size(); i++) {
            b_prime[i].resize(param.ell);

            for (int l = 0; l < param.ell; l++) {
                long temp = 0;
                for (int j = 0; j < param.n - partialSize; j++) {
                    temp = (temp + groupSK[i].secretSK[l][j] * A1[j]) % param.q;
                    temp = temp < 0 ? temp + param.q : temp;
                }
                if (b[l] < temp) {
                    b[l] += param.q;
                }
                b_prime[i][l] = (b[l] - temp) % param.q;
                // TODO: need gaussian error here for b_prime
            }
        }

        for (int i = 0; i< groupSK.size(); i++) {
            sharedSK[i] = groupSK[i].shareSK;
        }

        pk[w] = MREpk(b_prime, sharedSK);
    }

    return pk;
}


MREPublicKey MREgeneratePK(const PVWParam& param, vector<MREpk>& mrePK, const int crs, const int partySize = 8, const int partialSize = 40) {
    rng.seed(crs);
    std::uniform_int_distribution<std::mt19937::result_type> dist(0, 65536);

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

        int i = 0;
        for (; i < param.n - partialSize; i++) {
            A[i] = dist(rng) % param.q;
        }
        for (; i < param.n; i++) {
            A[i] = res[i - param.n + partialSize][0];
        }
        for (int i = 0; i < param.ell; i++) {
            b[i] = dist(rng) % param.q;
        }
        groupPK[w] = MREgroupPK(A, b);
    }

    return MREPublicKey(groupPK, mrePK);
}

bool verifyPK(const PVWParam& param, const MREgroupPK& groupPK, const vector<vector<uint64_t>>& b_prime, const vector<MREsharedSK>& recipientPK,
              const int partialSize = 40) {
    for (int r = 0; r < recipientPK.size(); r++) {
        for (int l = 0; l < param.ell; l++) {
            long b_temp = 0;
            for (int i = 0; i < param.n; i++) {
                if (i >= param.n - partialSize) {
                    b_temp = (b_temp + groupPK.A[i] * recipientPK[r][l][i - param.n + partialSize]) % param.q;
                }
            }
            if (b_prime[r][l] != b_temp) {
                return false;
            }
        }
    }

    return true;
}

void MREEncPK(PVWCiphertext& ct, const vector<int>& msg, const MREPublicKey& pk, const PVWParam& param) {
    NativeInteger q = param.q;
    ct.a = NativeVector(param.n);
    ct.b = NativeVector(param.ell);
    for(size_t i = 0; i < pk.groupPK.size(); i++){
        if (!verifyPK(param, pk.groupPK[i], pk.recipientPK[i].b_prime, pk.recipientPK[i].shareSK)) {
            // cout << "skip " << i << endl;
            continue;
        }
        if (rand()%2){
            for(int j = 0; j < param.n; j++){
                ct.a[j].ModAddFastEq(pk.groupPK[i].A[j], q);
            }
            for(int j = 0; j < param.ell; j++){
                ct.b[j].ModAddFastEq(pk.groupPK[i].b[j], q);
            }
        }
    }
    for(int j = 0; j < param.ell; j++){
        msg[j]? ct.b[j].ModAddFastEq(3*q/4, q) : ct.b[j].ModAddFastEq(q/4, q);
    }
}
