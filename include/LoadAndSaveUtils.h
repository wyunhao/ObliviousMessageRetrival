#pragma once

#include<iostream>
#include<fstream>
#include<string>
#include "MRE.h"
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
                temp = temp < 0 ? temp += params.q : temp;
            }
            compressed_result[i][j] = temp;
        }
    }

    return compressed_result;
}

void createDatabase(int num_of_transactions = 524288, int payloadSize = 306){
    for(int i = 0; i < num_of_transactions; i++){
        ofstream datafile;
        auto tempi = i % 65537;
        datafile.open ("../data/payloads/"+to_string(i)+".txt");
        for(int j = 0; j < payloadSize; j++){
            datafile << (65537 - tempi+j)%65537 << "\n";
        }
        datafile.close();
    }
}

vector<uint64_t> loadDataSingle(int i, const string folder = "payloads", int payloadSize = 306){
    vector<uint64_t> ret;

    ret.resize(payloadSize);
    ifstream datafile;
    datafile.open ("../data/"+folder+"/"+to_string(i)+".txt");
    for(int j = 0; j < payloadSize; j++){
        datafile >> ret[j];
    }
    datafile.close();

    return ret;
}


void saveSK(const PVWParam& param, const PVWsk sk) {
    ofstream datafile;
    datafile.open ("../data/clues/sk.txt");
    for (int i = 0; i < param.ell; i++) {
        for (int j = 0; j < param.n; j++) {
            datafile << sk[i][j].ConvertToInt() << "\n";
        }
    }
    datafile.close();
}


PVWsk loadSK(const PVWParam& param) {
    PVWsk sk(param.ell);
    ifstream datafile;
    datafile.open ("../data/clues/sk.txt");
    for (int i = 0; i < param.ell; i++) {
        sk[i] = NativeVector(param.n);
        for (int j = 0; j < param.n; j++) {
            uint64_t temp;
            datafile >> temp;
            sk[i][j] = temp;
        }
    }
    datafile.close();

    return sk;
}


void saveClues(const PVWCiphertext& clue, int transaction_num){
    ofstream datafile;
    datafile.open ("../data/clues/"+to_string(transaction_num)+".txt");

    for(size_t i = 0; i < clue.a.GetLength(); i++){
        datafile << clue.a[i].ConvertToInt() << "\n";
    }
    for(size_t i = 0; i < clue.b.GetLength(); i++){
        datafile << clue.b[i].ConvertToInt() << "\n";
    }

    datafile.close();
}

void saveGroupClues(const vector<vector<long>>& cluePolynomial, prng_seed_type seed, int transaction_num){
    ofstream datafile;
    datafile.open ("../data/cluePoly/"+to_string(transaction_num)+".txt");

    for(size_t i = 0; i < cluePolynomial.size(); i++){
        for (size_t j = 0; j < cluePolynomial[0].size(); j++) {
            datafile << cluePolynomial[i][j] << "\n";
        }
    }

    for (auto &i : seed) {
        datafile << i << "\n";
    }
    datafile.close();
}


void loadData(vector<vector<uint64_t>>& msgs, const int& start, const int& end, string folder = "payloads", int payloadSize = 306, int partySize = 1){
    msgs.resize((end-start) * partySize);
    for(int i = start; i < end; i++){
        msgs[i-start].resize(payloadSize);
        ifstream datafile;

        // duplicate each unique message |partySize| times
        for (int p = 0; p < partySize; p++) {
            datafile.open("../data/"+folder+"/"+to_string(i)+".txt");
            datafile.seekg(0, ios::beg);
            for(int j = 0; j < payloadSize; j++){
                datafile >> msgs[(i-start) * partySize + p][j];
            }
            datafile.close();
        }
    }
}

/**
 * @brief For ObliviousMultiplexer, the clue includes ((param.n + param.ell) * party_size_glb + prng_seed_count) elements.
 * Different from loadData, this function load the cluePoly.txt into two separate data structures, one is the normal cluPoly CM of size (clue_length) x (party_size),
 * one is randomness, and then use the randomness to generate a random matrix R of size (party_size * id_size) x party_size.
 * The resulted matrix CM*R^T, of size (clue_length) x (party_size * id_size).
 * Different from loadObliviousMultiplexerClues, this one does not multiply the result with target Id, since the later one is encrypted.
 * 
 * @param cluePoly 
 * @param randomness 
 * @param start 
 * @param end 
 * @param payloadSize 
 */
void loadOMClueWithRandomness(const PVWParam& params, vector<vector<uint64_t>>& cluePoly, const int& start, const int& end, int payloadSize = 306, int clueLength = 454) {
    vector<uint64_t> temp(payloadSize - prng_seed_uint64_count);
    vector<uint64_t> randomness(prng_seed_uint64_count);
    cluePoly.resize(end-start);

    int prng_seed_uint64_counter;
    prng_seed_type seed;

    for(int i = start; i < end; i++){
        cluePoly[i].resize(454 * id_size_glb * party_size_glb);
        ifstream datafile;

        datafile.open("../data/cluePoly/"+to_string(i)+".txt");
        datafile.seekg(0, ios::beg);
        for(int j = 0; j < payloadSize; j++){
            if (j < payloadSize - prng_seed_uint64_count) {
                datafile >> temp[j];
            } else {
                datafile >> randomness[j - (payloadSize - prng_seed_uint64_count)];
            }
        }
        datafile.close();

        prng_seed_uint64_counter = 0;
        for (auto &i : seed) {
            i = randomness[prng_seed_uint64_counter];
            prng_seed_uint64_counter++;
        }

        vector<vector<uint64_t>> random = generateRandomMatrixWithSeed(params, seed, id_size_glb * party_size_glb, party_size_glb);

        for (int c = 0; c < cluePoly[i].size(); c++) {
            int row_index = c / (id_size_glb * party_size_glb);
            int col_index = c % (id_size_glb * party_size_glb);
            long tempClue = 0;
            for (int k = 0; k < party_size_glb; k++) {
                tempClue = (tempClue + temp[row_index * party_size_glb + k] * random[col_index][k]) % params.q;
                tempClue = tempClue < 0 ? tempClue + params.q : tempClue;
            }
            cluePoly[i][c] = tempClue;
        }
    }
}


void loadClues(vector<PVWCiphertext>& clues, const int& start, const int& end, const PVWParam& param, int party_ind = 0, int partySize = 1){
    clues.resize(end-start);
    for(int i = start; i < end; i++){
        clues[i-start].a = NativeVector(param.n);
        clues[i-start].b = NativeVector(param.ell);

        ifstream datafile;
        datafile.open ("../data/clues/"+to_string(i * partySize + party_ind)+".txt");

        for(int j = 0; j < param.n; j++){
            uint64_t temp;
            datafile >> temp;
            clues[i-start].a[j] = temp;
        }

        for(int j = 0; j < param.ell; j++){
            uint64_t temp;
            datafile >> temp;
            clues[i-start].b[j] = temp;
        }
    }
}

// similar to loadClues but under Oblivious Multiplexer, load the clue polynomial coefficient matrix, and compute the clues based on target ID
void loadObliviousMultiplexerClues(vector<int> pertinent_msgs, vector<PVWCiphertext>& clues, const vector<int>& targetId, const int& start,
                                const int& end, const PVWParam& param, int clueLength = 454) {
    clues.resize(end-start);

    for (int i = start; i < end; i++) {
        prng_seed_type seed;
        vector<uint64_t> polyFlat = loadDataSingle(i, "cluePoly", clueLength * party_size_glb + prng_seed_uint64_count);
        vector<vector<long>> cluePolynomial(clueLength, vector<long>(party_size_glb));

        int prng_seed_uint64_counter = 0;
        for (auto &s : seed) {
            s = polyFlat[clueLength * party_size_glb + prng_seed_uint64_counter];
            prng_seed_uint64_counter++;
        }

        vector<vector<int>> ids(1);
        ids[0] = targetId;
        vector<vector<int>> compressed_id = compressVector(param, seed, generateExponentialExtendedVector(param, ids));

        vector<long> res(clueLength, 0);
        int res_ind = 0;

        clues[i-start].a = NativeVector(param.n);
        clues[i-start].b = NativeVector(param.ell);

        for (int c = 0; c < clueLength; c++) {
            for(int j = 0; j < compressed_id[0].size(); j++) {
                res[c] = (res[c] + polyFlat[c * compressed_id[0].size() + j] * compressed_id[0][j]) % param.q;
                res[c] = res[c] < 0 ? res[c] + param.q : res[c];
            }
        }

        for(int j = 0; j < param.n; j++, res_ind++){
            clues[i-start].a[j] = res[res_ind];
        }

        for(int j = 0; j < param.ell; j++, res_ind++){
            clues[i-start].b[j] = res[res_ind];
        }
    }
}