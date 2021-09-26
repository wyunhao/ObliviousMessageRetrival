#pragma once

#include<iostream>
#include<fstream>
#include<string>
#include <experimental/filesystem>

using namespace std;

void createDatabase(int num_of_transactions = 524288, int payloadSize = 306){
    for(int i = 0; i < num_of_transactions; i++){
        ofstream datafile;
        datafile.open ("../data/payloads/"+to_string(i)+".txt");
        for(int j = 0; j < payloadSize; j++){
            datafile << (65537 - i+j)%65537 << "\n";
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