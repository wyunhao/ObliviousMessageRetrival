#pragma once

using namespace std;

vector<vector<int>> generateExponentialExtendedVector(const PVWParam& params, vector<vector<int>> old_vec, const int extend_size = party_size_glb) {
    vector<vector<int>> extended_vec(old_vec.size());
    for (int i = 0; i < old_vec.size(); i++) {
        extended_vec[i].resize(old_vec[i].size() * extend_size);
        for (int j = 0; j < extended_vec[i].size(); j++) {
            extended_vec[i][j] = power(old_vec[i][j / extend_size], j % extend_size + 1, params.q);
        }
    }

    return extended_vec;
}

vector<vector<uint64_t>> generateRandomMatrixWithSeed(const PVWParam& params, prng_seed_type seed, int row, int col) {
    vector<vector<uint64_t>> random_matrix(row, vector<uint64_t>(col));

    auto rng = make_shared<Blake2xbPRNGFactory>(Blake2xbPRNGFactory(seed));
    RandomToStandardAdapter engine(rng->create());
    uniform_int_distribution<uint64_t> dist(0, params.q - 1);

    for (int i = 0; i < random_matrix.size(); i++) {
        for (int j = 0; j < random_matrix[0].size(); j++) {
            random_matrix[i][j] = dist(engine);
        }
    }

    return random_matrix;
}

vector<vector<int>> compressVector(const PVWParam& params, prng_seed_type seed, vector<vector<int>> ids, const int compress_size = party_size_glb) {
    vector<vector<int>> compressed_result(ids.size(), vector<int>(compress_size));
    vector<vector<uint64_t>> random_matrix = generateRandomMatrixWithSeed(params, seed, ids[0].size(), compress_size);

    for (int i = 0; i < compressed_result.size(); i++) {
        for (int j = 0; j < compressed_result[0].size(); j++) {
            long temp = 0;
            for (int k = 0; k < random_matrix.size(); k++) {
                temp = (temp + ids[i][k] * random_matrix[k][j]) % params.q;
                temp = temp < 0 ? temp + params.q : temp;
            }
            compressed_result[i][j] = temp;
        }
    }

    return compressed_result;
}