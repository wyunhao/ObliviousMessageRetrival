#pragma once

#include "seal/seal.h"
#include "client.h"
#include <algorithm>  
#include <map>

using namespace seal;
#define PROFILE


// Pick random values to satisfy multi-variable equation.
// For example, given x + y = 10, we might output {2, 8}.
void assignVariable(vector<vector<long>>& res, vector<int>& lhs, int rhs) {
    if (res.size() != lhs.size())
        cerr << "Coefficient and variable size not match." << endl;

    srand (time(NULL));
    int lastIndex = lhs.size() - 1;

    for (int i = lhs.size(); i > 0; i--) {
        if (lhs[i-1] != 0) {
            lastIndex = i-1;
            break;
        }
    }

    for (int i = 0; i < lhs.size(); i++) {
        if (lhs[i] != 0 && i != lastIndex) {
            res[i][0] = rand() % 65537;
            rhs = (rhs - (lhs[i] * res[i][0])) % 65537;
        }
    }

    res[lastIndex][0] = div_mod(rhs % 65537, lhs[lastIndex]);
    if (res[lastIndex][0] < 0)
        res[lastIndex][0] += 65537;
}

// Given solved variables with their values, update the remaining equations.
// For example, with equation; x + y + 2z = 10, and z = 2, updated equation would be x + y = 6.
void updateEquation(vector<vector<long>>& res, vector<vector<int>>& lhs, vector<vector<int>>& rhs) {
    for (int i = 0; i < lhs.size(); i++) {
        for (int j = 0; j < res.size(); j++) {
            if (res[j][0] > 0 && lhs[i][j] != 0) {
                rhs[i][0] = (rhs[i][0] - lhs[i][j] * res[j][0]) % 65537;
                lhs[i][j] = 0;
            }
        }
    }
}

// Pick random Zq elements as ID of recipients, in form of a (partySize x idSize) matrix.
vector<vector<int>>  initializeRecipientId(int partySize, int idSize, int mod = 65537) {
    srand (time(NULL));
    vector<vector<int>> ids(partySize, vector<int> (idSize, -1)); 

    for (int i = 0; i < ids.size(); i++) {
        for (int j = 0; j < ids[0].size(); j++) {
            ids[i][j] = rand() % mod;
        }
    }

    return ids;
}

// Read in the a part as RHS values for Oblivious Multiplexer polynomial.
void prepareClueRhs(vector<vector<int>>& rhs, const vector<PVWCiphertext> clues, int index) {
    for (int i = 0; i < rhs.size(); i++) {
        rhs[i][0] = clues[i].a[index].ConvertToInt();
    }
}



void solveCluePolynomial(vector<vector<int>>& lhs, vector<vector<int>>& rhs, int numToSolve, vector<vector<int>> ids) {
    vector<vector<long>> tryRes = equationSolving(lhs, rhs, -1);
    
    if (tryRes.empty()) {
        tryRes.resize(lhs[0].size(), vector<long>(1));
        while (!lhs.empty()) {
            assignVariable(tryRes, lhs[lhs.size() - 1], rhs[rhs.size() - 1][0]);
            lhs.pop_back();
            rhs.pop_back();
            updateEquation(tryRes, lhs, rhs);
        }
    }

    for (int j = 0; j < ids.size(); j++) {
        long checkpoint = 0;
        for (int i = 0; i < tryRes.size(); i++) {
            checkpoint = (checkpoint + tryRes[i][0] * ids[j][i]) % 65537;
        }
        cout << checkpoint % 65537 << endl;
    }
}


void obliviousMultiplexer() {
    int partySize = 16;
    int idSize = 20;

    vector<vector<int>> ids = initializeRecipientId(partySize, idSize); 
    vector<vector<int>> lhs = ids;


    vector<PVWCiphertext> clues;
    auto params = PVWParam(450, 65537, 1.3, 16000, 4); 

    loadClues(clues, 0, partySize, params);

    vector<vector<int>> rhs(partySize, vector<int>(1, -1));
    prepareClueRhs(rhs, clues, 0);

    solveCluePolynomial(lhs, rhs, partySize, ids);
}
