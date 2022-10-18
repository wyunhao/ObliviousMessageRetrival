#pragma once

#include <iostream>
#include <fstream>
#include <string>
#include <random>
#include "regevEncryption.h"
#include "seal/seal.h"
#include "global.h"
#include "client.h"
#include "MathUtil.h"

using namespace seal;

/**
 * @brief Multi-Recipient Encryption
 */
namespace mre {

    typedef vector<NativeVector> MREsharedSK;
    typedef vector<NativeVector> MREsecretSK;

    struct MREpk{
        vector<NativeVector> b_prime; // T x ell, double vector
        vector<MREsharedSK> shareSK; // T's ell x partialSize double vectors

        MREpk() {}
        MREpk(vector<NativeVector>& b_prime, vector<MREsharedSK>& shareSK)
        : b_prime(b_prime), shareSK(shareSK)
        {}
    };

    struct MREgroupPK {
        NativeVector A; // A1 || A2, where A1 of size param.n, A2 of size param.n-partialSize + partySize * param.ell (450 + 12*4)
        NativeVector b; // of size param.ell

        MREgroupPK() {}
        MREgroupPK(NativeVector& A, NativeVector& b)
        : A(A), b(b)
        {}
    };

    struct MREsk{
        MREsecretSK secretSK; // ell x param.n, double vector 
        MREsharedSK shareSK; // ell x partialSize, double vector

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

    vector<MREsk> MREgenerateSK(const PVWParam& param, const PVWsk& targetSK, const int partialSize = partial_size_glb, const int partySize = party_size_glb) {
        vector<MREsk> mreSK(partySize);

        for (int i = 0; i < partySize; i++) {
            // put the sk given in param as the first of the group
            // for pertinent messages, this will the recipient's sk, otherwise, a random sk will be passed in
            auto temp = i == 0 ? targetSK : PVWGenerateSecretKey(param);

            MREsecretSK leftSK(param.ell);
            MREsharedSK rightSK(param.ell);
            for (int l = 0; l < param.ell; l++) {
                leftSK[l] = NativeVector(param.n - partialSize);
                rightSK[l] = NativeVector(partialSize);

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

    vector<MREpk> MREgeneratePartialPK(const PVWParam& param, const vector<MREsk>& groupSK, prng_seed_type& seed,
                                       const int partialSize = partial_size_glb) {
        auto mrerng = make_shared<Blake2xbPRNGFactory>(Blake2xbPRNGFactory(seed));
        RandomToStandardAdapter engine(mrerng->create());
        std::uniform_int_distribution<std::mt19937::result_type> dist(0, param.q-1);

        vector<MREpk> pk(param.m);
        vector<uint64_t> A1(param.n - partialSize), b(param.ell);
        vector<NativeVector> b_prime(groupSK.size());
        vector<MREsharedSK> sharedSK(groupSK.size());

        for (int w = 0; w < param.m; w++) {
            for (int i = 0; i < param.n - partialSize; i++) {
                A1[i] = dist(engine) % param.q;
            }
            for (int i = 0; i < param.ell; i++) {
                b[i] = dist(engine) % param.q;
            }

            for (int i = 0; i < groupSK.size(); i++) {
                b_prime[i] = NativeVector(param.ell);

                for (int l = 0; l < param.ell; l++) {
                    long temp = 0;
                    for (int j = 0; j < param.n - partialSize; j++) {
                        temp = (temp + groupSK[i].secretSK[l][j].ConvertToInt() * A1[j]) % param.q;
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


    /**
     * @brief Similar to the main idea of ObliviousMultiplexer, besides the normal param.n (n=450) sk, we give 8 more elements (n=458, where partialSize = 8)
     * serving as the "sharedSK". By first exponential extended up to sk^party_size, we form a sharedSK matrix of size (ell*partySize) x (partialSize * partySize)
     * and then by multiplying it with a random matrix of size (partialSize*partySize) x (ell*partySize), we perserve it to be full rank = ell*partySize with
     * high probability. The resulted matrix is then used to solve a linear equation system such that f(sharedSK') = b_prime.
     * 
     * @param param PVWparam
     * @param mrePK of size param.w, MREpk 
     * @param seed seed for generating A1 and b, not published
     * @param exp_seed seed for generating random matrix, published in the clue
     * @param partySize party size
     * @param partialSize partial size
     * @return MREPublicKey 
     */
    MREPublicKey MREgeneratePK(const PVWParam& param, vector<MREpk>& mrePK, prng_seed_type& seed, prng_seed_type& exp_seed, const int partySize = party_size_glb,
                               const int partialSize = partial_size_glb) {
        auto mrerng = make_shared<Blake2xbPRNGFactory>(Blake2xbPRNGFactory(seed));
        RandomToStandardAdapter engine(mrerng->create());
        std::uniform_int_distribution<std::mt19937::result_type> dist(0, param.q-1);

        vector<MREgroupPK> groupPK(param.m);
        for (int w = 0; w < param.m; w++) {
            NativeVector A(param.n - partialSize + param.ell * partySize), b(param.ell);
            vector<vector<int>> rhs(partySize), lhs(partySize), old_shared_sk(partySize);
            vector<vector<vector<long>>> res(param.ell);

            for (int i = 0; i < param.ell; i++) {
                for (int p = 0; p < partySize; p++) {
                    rhs[p].resize(1);
                    rhs[p][0] = mrePK[w].b_prime[p][i].ConvertToInt();

                    old_shared_sk[p].resize(partialSize);

                    for (int j = 0; j < partialSize; j++) {
                        old_shared_sk[p][j] = mrePK[w].shareSK[p][i][j].ConvertToInt();
                    }
                }

                vector<vector<int>> extended_shared_sk = generateExponentialExtendedVector(param, old_shared_sk, partySize);
                lhs = compressVector(param, exp_seed, extended_shared_sk, partySize);
                res[i] = equationSolvingRandom(lhs, rhs, -1);
            }

            int i = 0, j = 0;
            for (; i < param.n - partialSize; i++) {
                A[i] = dist(engine) % param.q;
            }
            for (; j < param.ell * partySize; i++, j++) {
                int ell_ind = j / partySize;
                int party_ind = j % partySize; 
                A[i] = res[ell_ind][party_ind][0];
            }
            for (int i = 0; i < param.ell; i++) {
                b[i] = dist(engine) % param.q;
            }

            groupPK[w] = MREgroupPK(A, b);
        }

        return MREPublicKey(groupPK, mrePK);
    }

    bool verifyPK(const PVWParam& param, prng_seed_type& exp_seed, const MREgroupPK& groupPK, const vector<NativeVector>& b_prime, const vector<MREsharedSK>& recipientPK,
                  const int partialSize = partial_size_glb, const int partySize = party_size_glb) {

        vector<vector<uint64_t>> random_matrix = generateRandomMatrixWithSeed(param, exp_seed, partialSize * partySize, partySize);;
        vector<vector<int>> shared_SK(partySize), extended_shared_sk;
        vector<int> extended_A(partialSize * partySize);
        for (int l = 0; l < param.ell; l++) {
            for (int p = 0; p < partySize; p++) {
                shared_SK[p].resize(partialSize);
                for (int j = 0; j < partialSize; j++) {
                    shared_SK[p][j] = recipientPK[p][l][j].ConvertToInt();
                }
            }

            extended_shared_sk = generateExponentialExtendedVector(param, shared_SK, partySize);

            for (int i = 0; i < extended_A.size(); i++) {
                long temp = 0;
                for (int j = 0; j < partySize; j++) {
                    temp = (temp + random_matrix[i][j] * groupPK.A[l * partySize + j + param.n - partialSize].ConvertToInt()) % param.q;
                    temp = temp < 0 ? temp + param.q : temp;
                }
                extended_A[i] = temp;
            }

            for (int r = 0; r < partySize; r++) {
                long temp =0;
                for (int i = 0; i < extended_A.size(); i++) {
                    temp = (temp + extended_A[i] * extended_shared_sk[r][i]) % param.q;
                    temp = temp < 0 ? temp + param.q : temp;
                }
                if (b_prime[r][l] != temp) {
                    return false;
                }
            }
        }

        return true;
    }

    void MREEncPK(PVWCiphertext& ct, const vector<int>& msg, const MREPublicKey& pk, const PVWParam& param, prng_seed_type& exp_seed, const int partialSize = partial_size_glb,
                  const int partySize = party_size_glb) {
        prng_seed_type seed;
        for (auto &i : seed) {
            i = random_uint64();
        }

        auto rng = make_shared<Blake2xbPRNGFactory>(Blake2xbPRNGFactory(seed));
        RandomToStandardAdapter engine(rng->create());
        uniform_int_distribution<uint64_t> dist(0, 1);

        NativeInteger q = param.q;
        ct.a = NativeVector(param.n - partialSize + param.ell * partySize);
        ct.b = NativeVector(param.ell);
        for(size_t i = 0; i < pk.groupPK.size(); i++){
            if (!verifyPK(param, exp_seed, pk.groupPK[i], pk.recipientPK[i].b_prime, pk.recipientPK[i].shareSK)) {
                continue;
            }
            if (dist(engine)){
                for(int j = 0; j < pk.groupPK[i].A.GetLength(); j++){
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
}
