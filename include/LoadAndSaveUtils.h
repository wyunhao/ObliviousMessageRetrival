#pragma once

#include<iostream>
#include<fstream>
#include<string>
#include <limits>
#include "MRE.h"
#include "MathUtil.h"
using namespace std;

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

vector<uint64_t> loadDataSingle(int i, const string folder = "payloads", int payloadSize = 306) {
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

    for (size_t i = 0; i < clue.a.GetLength(); i++) {
        datafile << clue.a[i].ConvertToInt() << "\n";
    }
    for (size_t i = 0; i < clue.b.GetLength(); i++) {
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

void saveCluesWithRandomness(const PVWCiphertext& clue, const int transaction_num, prng_seed_type seed) {
    ofstream datafile;
    datafile.open ("../data/clues/"+to_string(transaction_num)+".txt");

    for (size_t i = 0; i < clue.a.GetLength(); i++) {
        datafile << clue.a[i].ConvertToInt() << "\n";
    }
    for (size_t i = 0; i < clue.b.GetLength(); i++) {
        datafile << clue.b[i].ConvertToInt() << "\n";
    }
    for (auto &i : seed) {
        datafile << i << "\n";
    }
    datafile.close();
}

void writeVectorToFile(vector<uint64_t> vec, const int file_num, const string folderName) {
    ofstream datafile;
    datafile.open ("../data/" + folderName + "/"+to_string(file_num)+".txt");

    for(size_t i = 0; i < vec.size(); i++){
        datafile << vec[i] << "\n";
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


ifstream& gotoLine(ifstream& file, unsigned int num){
    file.seekg(ios::beg);
    for (int i = 0; i < num; i++) {
        file.ignore(numeric_limits<streamsize>::max(), '\n');
    }
    return file;
}

uint64_t loadEntryFromProcessedCM(const int trans_num, const int entry_index) {
    uint64_t entry = 0;

    ifstream datafile;
    datafile.open("../data/processedCM/"+to_string(trans_num)+".txt");
    if (entry_index) gotoLine(datafile, entry_index);
    datafile >> entry;
    datafile.close();

    return entry;
}


void prepareRotatedVectorOfA(const PVWParam& param) {
    int tempn, tempId;
    for (tempn = 1; tempn < param.n; tempn *= 2) {}
    for (tempId = 1; tempId < id_size_glb * party_size_glb; tempId *= 2) {}

    int iteration = ceil(tempId / batch_ntt_glb);

    for (int it = 0; it < iteration; it++) {
        for (int i = 0; i < tempn; i++) {
            for (int eid_index = it*batch_ntt_glb; eid_index < (it+1)*batch_ntt_glb; eid_index++) {
                vector<uint64_t> vectorOfA(poly_modulus_degree_glb);
                for (int j = 0; j < poly_modulus_degree_glb; j++) {
                    int row_index = (j + i) % tempn;
                    int col_index = (j + eid_index) % (tempId);
                    if (row_index >= param.n || col_index >= id_size_glb * party_size_glb) {
                        vectorOfA[j] = 0;
                    } else {
                        vectorOfA[j] = loadEntryFromProcessedCM(j, row_index * (id_size_glb*party_size_glb) + col_index);
                    }
                }

                int eid_index_clear = eid_index % batch_ntt_glb;
                writeVectorToFile(vectorOfA, it*tempn*batch_ntt_glb + i*batch_ntt_glb + eid_index_clear, "vectorOfA");
            }
        }
    }
}


void prepareRotatedVectorOfB(const PVWParam& param) {
    int tempn;
    for (tempn = 1; tempn < id_size_glb * party_size_glb; tempn *= 2) {}

    for (int i = 0; i < tempn; i++) {
        for (int e = 0; e < param.ell; e++) {
            vector<uint64_t> vectorOfB(poly_modulus_degree_glb);
            for (int j = 0; j < poly_modulus_degree_glb; j++) {
                int the_index = (i + j) % tempn;
                if (the_index >= id_size_glb * party_size_glb) {
                    vectorOfB[j] = 0;
                } else {
                    vectorOfB[j] = loadEntryFromProcessedCM(j, (param.n + e) * (id_size_glb * party_size_glb) + the_index);
                }
            }

            writeVectorToFile(vectorOfB, i*param.ell + e, "vectorOfB");
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
 * This function will save the processed matrix back to the file system
 * 
 * @param randomness 
 * @param start 
 * @param end 
 * @param payloadSize = clueLength * T', where T' = party_size + extra_secure_length
 */
void loadOMClueWithRandomness(const PVWParam& params, vector<vector<uint64_t>>& cluePoly, const int& start, const int& end,
                              int payloadSize = 306, int clueLength = 454) {
    vector<uint64_t> temp(payloadSize - prng_seed_uint64_count);
    vector<uint64_t> randomness(prng_seed_uint64_count);
    cluePoly.resize(end-start);
    vector<uint64_t> processed_cm(454 * id_size_glb * party_size_glb);

    int prng_seed_uint64_counter;
    prng_seed_type seed;

    for(int i = start; i < end; i++){
        cluePoly[i-start].resize(454 * id_size_glb * party_size_glb);
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

        vector<vector<uint64_t>> random = generateRandomMatrixWithSeed(params, seed, id_size_glb * party_size_glb,
                                                                       party_size_glb + secure_extra_length_glb);

        for (int c = 0; c < processed_cm.size(); c++) {
            int row_index = c / (id_size_glb * party_size_glb);
            int col_index = c % (id_size_glb * party_size_glb);
            long tempClue = 0;
            for (int k = 0; k < party_size_glb + secure_extra_length_glb; k++) {
                tempClue = (tempClue + temp[row_index * (party_size_glb + secure_extra_length_glb) + k] * random[col_index][k]) % params.q;
                tempClue = tempClue < 0 ? tempClue + params.q : tempClue;
            }
            cluePoly[i-start][c] = tempClue;
            processed_cm[c] = tempClue;
        }

        writeVectorToFile(processed_cm, i, "processedCM");
    }
}


vector<vector<uint64_t>> batchLoadOMClueWithRandomness(const PVWParam& params, const int& start, const int& end, int payloadSize) {
    vector<vector<uint64_t>> processed_cm(end-start);

    for(int i = start; i < end; i++){
        processed_cm[i-start].resize(454 * id_size_glb * party_size_glb);
        ifstream datafile;

        datafile.open("../data/processedCM/"+to_string(i)+".txt");
        datafile.seekg(0, ios::beg);
        for(int c = 0; c < processed_cm[i-start].size(); c++){
            datafile >> processed_cm[i-start][c];
        }
        datafile.close();
    }

    return processed_cm;
}


void loadFixedGroupClues(vector<PVWCiphertext>& clues, const int& start, const int& end, const PVWParam& param, const int partySize = party_size_glb, const int partialSize = partial_size_glb){
    clues.resize(end-start);
    int a1_size = param.n - partialSize, old_a2_size = param.ell * partySize, new_a2_size = param.ell * partialSize * partySize;

    vector<int> old_a2(old_a2_size);
    vector<uint64_t> randomness(prng_seed_uint64_count);
    int prng_seed_uint64_counter;
    prng_seed_type seed;

    for(int i = start; i < end; i++){
        clues[i-start].a = NativeVector(a1_size + new_a2_size);
        clues[i-start].b = NativeVector(param.ell);

        ifstream datafile;
        datafile.open ("../data/clues/"+to_string(i)+".txt");

        for (int j = 0; j < a1_size; j++) {
            uint64_t temp;
            datafile >> temp;
            clues[i-start].a[j] = temp;
        }

        for (int j = 0; j < old_a2_size; j++) {
            datafile >> old_a2[j];
        }

        for (int j = 0; j < param.ell; j++) {
            uint64_t temp;
            datafile >> temp;
            clues[i-start].b[j] = temp;
        }

        for (int j = 0; j < prng_seed_uint64_count; j++) {
            datafile >> randomness[j];
        }

        datafile.close();

        prng_seed_uint64_counter = 0;
        for (auto &i : seed) {
            i = randomness[prng_seed_uint64_counter];
            prng_seed_uint64_counter++;
        }

        vector<vector<uint64_t>> random_matrix = generateRandomMatrixWithSeed(param, seed, partialSize * partySize, partySize);

        for (int l = 0; l < param.ell; l++) {
            for (int c = 0; c < partialSize * partySize; c++) {
                long temp = 0;
                for (int k = 0; k < partySize; k++) {
                    temp = (temp + old_a2[l * partySize + k] * random_matrix[c][k]) % param.q;
                    temp = temp < 0 ? temp + param.q : temp;
                }
                clues[i-start].a[l * partySize * partialSize + c + a1_size] = temp;
            }
        }
    }
}

// similar to loadClues but under Oblivious Multiplexer, load the clue polynomial coefficient matrix, and compute the clues based on target ID
void loadObliviousMultiplexerClues(vector<int> pertinent_msgs, vector<PVWCiphertext>& clues, const vector<int>& targetId, const int& start,
                                const int& end, const PVWParam& param, int clueLength = 454) {
    clues.resize(end-start);

    for (int i = start; i < end; i++) {
        prng_seed_type seed;
        vector<uint64_t> polyFlat = loadDataSingle(i, "cluePoly", clueLength * (party_size_glb + secure_extra_length_glb) + prng_seed_uint64_count);

        int prng_seed_uint64_counter = 0;
        for (auto &s : seed) {
            s = polyFlat[clueLength * (party_size_glb + secure_extra_length_glb) + prng_seed_uint64_counter];
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