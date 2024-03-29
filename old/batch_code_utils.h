#pragma once

#include <iostream>
#include <vector>
#include <cmath>
#include <algorithm>
#include <string>
#include <random>
#include <time.h>
#include <chrono>
#include <NTL/BasicThreadPool.h>
#include <cassert>
using namespace std;


int n = pow(10,7);
int k = 1000;
int N = pow(2,5);
int c = 10;
int m = k*1;
vector<int> pertinentCollection(n, 0);
vector<int> GTpertinentCollection(n, 0);

class EachTransaction {      
  public:             
    int ithTransaction;
    int ithSlot;
    int ithBucket;
    int weight;
    bool pertinent;

    EachTransaction(){};
    EachTransaction(int index, int N) {
        ithTransaction = index;
        ithSlot = N;
        pertinent = false;
    };
    ~EachTransaction(){};
    void AssignBucket(int whichBucket) {
        ithBucket = whichBucket;
    };
    void AssignWeight(int weightW) {
        weight = weightW;
    };
    void setPertinent() {
        pertinent = true;
    };
};

class EachBucket {
    public:
        vector<EachTransaction> transInBucket;
        vector<int> allSlots; // how many weights/items are in a single slot
        vector<int> allSlotsWeights; // the sumed weights in the slots
        bool iscollided;
        vector<int> allTrans; // totally n transactions. Not used for now
        vector<int> collidedSlots; // the list of all collieded slots

    EachBucket(){iscollided = false; allSlots = vector<int> (N, 0); \
                    allSlotsWeights = vector<int> (N, 0); allTrans = vector<int> (0, 0);};
    ~EachBucket(){};
    void putTransInBucket(EachTransaction t) {
        transInBucket.push_back(t);
        //if(rand() % 10000 == 0){
        //cout << transInBucket[transInBucket.size() - 1].ithTransaction << " "\
        //<< transInBucket[transInBucket.size() - 1].ithSlot << " "\
        //<< transInBucket[transInBucket.size() - 1].ithBucket << " "\
        //<< transInBucket[transInBucket.size() - 1].weight << " "\
        //<< transInBucket[transInBucket.size() - 1].pertinent << " " << endl;
        //cout << t.ithTransaction << " "\
        //<< t.ithSlot << " "\
        //<< t.ithBucket << " "\
        //<< t.weight << " "\
        //<< t.pertinent << " " << endl;
        //}
        
    };
    //~EachBucket() {for(int i = 0; i < transInBucket.size(); i++) {delete transInBucket[i];}};
};

////////////////////////////// Initialization

void Initialization(vector<vector<EachTransaction>>& allvs, vector<int>& pertinentV, vector<EachBucket>& allBuckets){
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;

    //1. sample random pertinent samples
    vector<int> allTransactions(n);
    generate(allTransactions.begin(), allTransactions.end(), [n = 0] () mutable { return n++; });
    shuffle (allTransactions.begin(), allTransactions.end(), default_random_engine(time(NULL)));
    pertinentV = vector<int>(allTransactions.begin(), allTransactions.begin()+k);

    //2. initialize all transactions
    vector<EachTransaction> v(n);
    generate(v.begin(), v.end(), [n = 0] () mutable { return EachTransaction(n++, rand()%N); });
    for(int i = 0; i < k; i++) {v[pertinentV[i]].setPertinent(); GTpertinentCollection[pertinentV[i]] = 1;}
    for(int i = 0; i < c; i++) {allvs[i] = v;};

    //3. initialize all weights
    int weightCounter = 1;
    for(int i = 0; i < c; i++){
        for(int j = 0; j < n; j++){
            allvs[i][j].AssignWeight(weightCounter++);
        }
    }

    //time_start = chrono::high_resolution_clock::now();
    //4. assign buckets randomly
    srand(time(NULL));
    vector<int> alreadyTaken(c, -1);
    for(int j = 0; j < n; j++){
        for(int i = 0; i < c; i++){
            int randBkt = rand()%m;
            while(count(alreadyTaken.begin(), alreadyTaken.end(), randBkt))
            {
                randBkt = rand()%m;
            }
            alreadyTaken[i] = randBkt;
            allvs[i][j].AssignBucket(randBkt);
        }
        alreadyTaken.clear();
    }
    //time_end = chrono::high_resolution_clock::now();
    NTL::SetNumThreads(2);
    //time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    //cout << "Done213 [" << time_diff.count() << " microseconds]" << endl;
    //time_start = chrono::high_resolution_clock::now();
    //NTL_EXEC_RANGE(c, first, last)
    for(int i = 0; i < c; i++){
        for(int j = 0; j < n; j++){
            allBuckets[allvs[i][j].ithBucket].putTransInBucket(allvs[i][j]);
        }
    }
    //NTL_EXEC_RANGE_END
    //time_end = chrono::high_resolution_clock::now();
    //time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    //cout << "Done123 [" << time_diff.count() << " microseconds]" << endl;
}

/////////////////////////////// Dir1 and Dir2

double collisionSlotsRate(EachBucket& v){
    
    for(int i = 0; i < v.transInBucket.size(); i++){
        if (v.transInBucket[i].pertinent){
            v.allSlots[v.transInBucket[i].ithSlot] += 1;
            v.allSlotsWeights[v.transInBucket[i].ithSlot] += v.transInBucket[i].weight;
            //v.allTrans[v.transInBucket[i].ithTransaction] += 1;
        }
    }
    int ret = 0;
    for(int i = 0; i < N; i++){
        if(v.allSlots[i] >= 2){
            ret += 1;
            v.collidedSlots.push_back(i);
        }
    }
    if(ret != 0)
        v.iscollided = true;
    return ret/double(N);
}

vector<int> direction2(vector<EachBucket>& allBuckets){
    int numOfCollidedBuckets = 0;
    for(int i = 0; i < allBuckets.size(); i++){
        if(collisionSlotsRate(allBuckets[i]) != 0){
            numOfCollidedBuckets += 1;
        }
    }

    vector<int> ret(2);
    ret[0] = numOfCollidedBuckets;

    return ret;
}

/////////////////////////////// Dir3

template <typename T>
vector<T> possibleSums(const std::vector<T>& v, std::size_t count, vector<vector<size_t>>& retIndex)
{
    int nCr = tgamma(int(v.size())+1)/tgamma(count+1)/tgamma(int(v.size()) - count+1);
    vector<T> ret;

    size_t K = count;
    size_t N = v.size();
    std::string bitmask(K, 1); // K leading 1's
    bitmask.resize(N, 0); // N-K trailing 0's
 
    // print integers and permute bitmask
    do {
        T temp(0);
        vector<size_t> tempvec;
        for (size_t i = 0; i < N; ++i) // [0..N-1] integers
        {
            if (bitmask[i]) {temp += v[i]; tempvec.push_back(i);}
        }
        ret.push_back(temp);
        retIndex.push_back(tempvec);
    } while (std::prev_permutation(bitmask.begin(), bitmask.end()));
//
    //if(!(count <= v.size())){
    //    cout << count << " " << v.size() << endl;
    //    exit(1);
    //}
    //std::vector<bool> bitset(count, 1);
    //bitset.resize(v.size(), 0);
//
    //int counter = 0;
    //do {
    //    for (std::size_t i = 0; i != v.size(); ++i) {
    //        if (bitset[i]) {
    //            ret[counter] += v[i];
    //        }
    //    }
    //    counter += 1;
    //} while (std::prev_permutation(bitset.begin(), bitset.end()));

    return ret;
}

int bigcount = 0;
bool checkUnique(const std::vector<int>& possibleWeights, size_t num_of_collisions, int theCollidedResult){
    vector<vector<size_t>> retIndex;
    auto res = possibleSums(possibleWeights, num_of_collisions, retIndex);
    int theCount = count(res.begin(), res.end(), theCollidedResult);
    if(theCount <= 0)
        cerr << "Something went wrong in check unique, please check!" << endl;
    
    if(theCount == 1){
        for(int i = 0; i < retIndex.size(); i++){
            if(theCollidedResult == res[i]){
                auto theIndices = retIndex[i];
                for(int j = 0; j < theIndices.size(); j++){
                    int tempTheWeight = possibleWeights[theIndices[j]] - 1; // weight start from 1 while slots start from 0
                    tempTheWeight %= n;
                    pertinentCollection[tempTheWeight] = 1;
                }
            }
        }
    }

    // Just for test and debug purpose 
    //if((theCount != 1) && (bigcount <= 2)){
    //    cout << "\n xxxxxxxxxxxxxxxxxx" << endl;
    //    for(int i = 0; i < possibleWeights.size(); i++){
    //        cout << possibleWeights[i] << " ";
    //    }
    //    cout << endl;
    //    for(int i = 0; i < res.size(); i++){
    //        cout << res[i] << " ";
    //    }
    //    cout << endl;
    //    cout << theCollidedResult << endl;
    //    cout << theCount << endl;;
    //    cout << num_of_collisions << endl;
    //    bigcount += 1;
    //    exit(1);
    //}
    // Just for test and debug purpose 

    return (theCount == 1);
}

int selfResolving(vector<EachBucket>& allBuckets){
    int collidedCount = 0;
    for(int i = 0; i < allBuckets.size(); i++)
    {
        vector<int> possibleWeights;
        // Remove duplicates
        sort( allBuckets[i].collidedSlots.begin(), allBuckets[i].collidedSlots.end() );
        allBuckets[i].collidedSlots.erase(unique(allBuckets[i].collidedSlots.begin(), allBuckets[i].collidedSlots.end()), allBuckets[i].collidedSlots.end());
        // Remove duplicates
        bool isSelfResolvable = true;
        vector<int> newCollidedIndices;
        while(allBuckets[i].collidedSlots.size() != 0) // check all the collided vectors
        {
            int theSlot = allBuckets[i].collidedSlots.back(); allBuckets[i].collidedSlots.pop_back(); // check the last slot get collided and pop it out from the original vector
            for(int j = 0; j < allBuckets[i].transInBucket.size(); j++){
                if (allBuckets[i].transInBucket[j].ithSlot == theSlot){
                    possibleWeights.push_back(allBuckets[i].transInBucket[j].weight);
                }
            }
            if(!checkUnique(possibleWeights, allBuckets[i].allSlots[theSlot], allBuckets[i].allSlotsWeights[theSlot]))
            {
                isSelfResolvable = false; // if not resolvable, add to the new collided list
                newCollidedIndices.push_back(theSlot);
            }
            else
            {
                allBuckets[i].allSlots[theSlot] = 1; // mark that slot as not collided though it might not matter
                allBuckets[i].allSlotsWeights[theSlot] = 0; // mark that slot as not collided though it might not matter
            }
            possibleWeights.clear();
        }
        
        if(isSelfResolvable)
            allBuckets[i].iscollided = false; // collided weights are still there but not important
        else{
            collidedCount += 1;
            allBuckets[i].collidedSlots = newCollidedIndices; // new collided places
        }
    }
    return collidedCount;
}


int unitProporgation(vector<EachBucket>& allBuckets, vector<vector<EachTransaction>>& allvs){
    int collidedCount = 0;
    for(int i = 0; i < allBuckets.size(); i++)
    {
        if(allBuckets[i].iscollided)
        {
            vector<int> newCollidedList;
            while(allBuckets[i].collidedSlots.size() != 0) // check all the collided vectors
            {
                // cout << allBuckets[i].collidedSlots.size() << endl;
                int theSlot = allBuckets[i].collidedSlots.back(); allBuckets[i].collidedSlots.pop_back(); // check the last slot get collided and pop it out from the original vector
                // check for all the transactions that match this slot
                for(int j = 0; j < allBuckets[i].transInBucket.size(); j++){
                    int theithtrans;
                    if ((allBuckets[i].transInBucket[j].pertinent) && (allBuckets[i].transInBucket[j].ithSlot == theSlot)){
                        bool solved = false;
                        theithtrans = allBuckets[i].transInBucket[j].ithTransaction;
                        for(int j = 0; j < c; j++){
                            EachTransaction* ptr = & allvs[j][theithtrans];
                            if(!allBuckets[ptr->ithBucket].iscollided){
                                solved = true;
                                break;
                            }
                            //else if(allBuckets[ptr->ithBucket].allSlots[theSlot] == 1){
                            //    solved = true;
                            //    break;
                            //}
                        }
                        //cout << allBuckets[i].allSlots[theSlot] << endl;
                        if(solved){
                            allBuckets[i].allSlots[theSlot] -= 1;
                            allBuckets[i].allSlotsWeights[theSlot] -= allBuckets[i].transInBucket[j].weight;
                            if(allBuckets[i].allSlots[theSlot] = 1)
                            {
                                break;
                            }
                        }
                    }
                }
                if(allBuckets[i].allSlots[theSlot] > 1)
                {
                    newCollidedList.push_back(theSlot);
                }
            }
            if(newCollidedList.size() == 0){
                allBuckets[i].iscollided = false;
            }
            else{
                collidedCount += 1;
                allBuckets[i].collidedSlots = newCollidedList;
            }
        }
    }
    return collidedCount;
}

int fillOutpertinentCollection(vector<EachBucket>& allBuckets, vector<vector<EachTransaction>>& TransactionsAllCopies){
    for(int i = 0; i < m; i++){
        for(int j = 0; j < N; j++){
            if(allBuckets[i].allSlots[j] == 1){
                auto theWeight = allBuckets[i].allSlotsWeights[j] - 1;
                theWeight %= n;
                pertinentCollection[theWeight] = 1;
            }
        }
    }
    //int pert_counter = 0;
    //for(int i = 0; i < n; i++)
    //    if(GTpertinentCollection[i] || pertinentCollection[i])
    //        cout << i << " " << GTpertinentCollection[i] << " " << pertinentCollection[i] << endl;
    //cout << pert_counter << endl;
    unitProporgation(allBuckets, TransactionsAllCopies);
    return selfResolving(allBuckets);
}

//int main(){
//    vector<vector<EachTransaction>> TransactionsAllCopies(c);
//    vector<int> pertinentTrans(k);
//    vector<EachBucket> allBuckets(m);
//    chrono::high_resolution_clock::time_point time_start, time_end;
//    chrono::microseconds time_diff;//

//    time_start = chrono::high_resolution_clock::now();
//    Initialization(TransactionsAllCopies, pertinentTrans, allBuckets);
//    time_end = chrono::high_resolution_clock::now();
//    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
// 
//    EachBucket tst; tst.transInBucket = TransactionsAllCopies[0];
//    cout << "Collision Rate: " << collisionSlotsRate(tst) << endl;
//    cout << "Direction 2: how many buckets collided: " << direction2(allBuckets)[0] << endl;
//    cout << "Direction 3: how many buckets collided: " << fillOutpertinentCollection(allBuckets, TransactionsAllCopies) << endl;
//    int pert_counter = 0;
//    for(int i = 0; i < n; i++)
//        if(pertinentCollection[i]){
//            pert_counter += 1;
//        }
//    cout << pert_counter << endl;
//    //cout << "Direction 3: how many buckets collided: " << selfResolving(allBuckets) << endl;
//    cout << "Done [" << time_diff.count() << " microseconds]" << endl;
//}
