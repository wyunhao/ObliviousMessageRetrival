#pragma once

#include<iostream>
#include<fstream>
#include<string>
#include <experimental/filesystem>

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

vector<vector<uint64_t>> loadData(int num_of_transactions = 524288, int payloadSize = 306){
    vector<vector<uint64_t>> ret(num_of_transactions);
    for(int i = 0; i < num_of_transactions; i++){
        ret[i].resize(payloadSize);
        ifstream datafile;
        datafile.open ("../data/payloads/"+to_string(i)+".txt");
        for(int j = 0; j < payloadSize; j++){
            datafile >> ret[i][j];
        }
        datafile.close();
    }
    return ret;
}

vector<uint64_t> loadDataSingle(int i, int payloadSize = 306){
    vector<uint64_t> ret;

    ret.resize(payloadSize);
    ifstream datafile;
    datafile.open ("../data/payloads/"+to_string(i)+".txt");
    for(int j = 0; j < payloadSize; j++){
        datafile >> ret[j];
    }
    datafile.close();

    return ret;
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

void loadData(vector<vector<uint64_t>>& msgs, const int& start, const int& end, int payloadSize = 306){
    msgs.resize(end-start);
    for(int i = start; i < end; i++){
        // cout << i << " " << start << " " << end << " " << payloadSize;
        msgs[i-start].resize(payloadSize);
        ifstream datafile;
        datafile.open("../data/payloads/"+to_string(i)+".txt");
        for(int j = 0; j < payloadSize; j++){
            // cout << " " << j << ",";
            datafile >> msgs[i-start][j];
        }
        // cout << endl;
        datafile.close();
    }
    // cout << msgs.size() << " ??? " << endl;
}

void loadClues(vector<PVWCiphertext>& clues, const int& start, const int& end, const PVWParam& param){
    clues.resize(end-start);
    for(int i = start; i < end; i++){
        clues[i-start].a = NativeVector(param.n);
        clues[i-start].b = NativeVector(param.ell);

        ifstream datafile;
        datafile.open ("../data/clues/"+to_string(i)+".txt");

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

//void createSICforEachTransaction(int n = 450, int q = 65537, double std_dev = 1.2, int m = 8100, int num_of_transactions = 524288, int num_of_parties = 32768){
//    for(int i = 0; i < num_of_parties; i++){
//        auto params = regevParam(n, q, std_dev, m);
//
//        // generate and save sk
//        auto sk = regevGenerateSecretKey(params);
//        string newdir = "../data/sk/"+to_string(i);
//        std::experimental::filesystem::create_directories(newdir);
//        string filenameIncludingFolder = newdir+"/party_"+to_string(i)+".txt";
//        ofstream outputfile(filenameIncludingFolder);
//        for(size_t j = 0; j < sk.GetLength(); j++){
//            outputfile << sk[j] << "\n";
//        }
//        outputfile.close();
//
//        // generate pk
//        auto pk = regevGeneratePublicKey(params, sk);
//        for(int k = i; k < num_of_transactions; k += num_of_parties){
//            int msg = 1;
//            string newdir = "../data/SICsender/"+to_string(k);
//            std::experimental::filesystem::create_directories(newdir);
//            for(int y = 0; y <= 3; y++){
//                int msg_dec = -1;
//                regevCiphertext temp;
//                regevEncPK(temp, msg, pk, params);
//                regevDec(msg_dec, temp, sk, params);
//                if(msg_dec == 1){
//                    string filenameIncludingFolder = newdir+"/"+to_string(y)+".txt";
//                    ofstream outputfile(filenameIncludingFolder);
//                    outputfile << temp.b << "\n";
//                    for(size_t x = 0; x < temp.a.GetLength(); x++){
//                        outputfile << temp.a[x] << "\n";
//                    }
//                    outputfile.close();
//                    continue;
//                }
//                else if(msg_dec == 0)
//                    cerr << "Error in generating SICs!" << endl;
//                else
//                    cerr << "Neither 1 nor 0!" << endl;
//                
//            }
//        }
//    }
//}
//
//void readSICs(vector<vector<regevCiphertext>>& allSICs, int loadingSize = 524288, int n = 450){
//    allSICs.resize(4);
//    for(int i = 0; i < loadingSize; i++){
//        allSICs[i].resize(loadingSize);
//        for(int j = 0; j <= 3; j++){
//            cout << i << j << endl;
//            ifstream file("./SICsender/"+to_string(i)+"/"+to_string(j)+".txt");
//            cout << i << j << endl;
//            int temp;
//            file >> temp;
//            allSICs[j][i].b = temp;
//            allSICs[j][i].a = NativeVector(n);
//            for(int k = 0; k < n; k++){
//                cout << k << endl;
//                file >> temp;
//                allSICs[j][i].a[k] = temp;
//            }
//            file.close();
//        }
//    }
//}