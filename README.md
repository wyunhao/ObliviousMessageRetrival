# ObliviousMessageRetrival

### Dependency: Palisade, SEAL

```
git clone https://github.com/tfhe/tfhe
cd palisade
mkdir build
cd build
cmake ../src -DENABLE_TESTS=on -DENABLE_FFTW=on -DCMAKE_BUILD_TYPE=debug
make
make install
```

```
git clone https://github.com/microsoft/SEAL
cd SEAL
cmake -S . -B build
cmake --build build
sudo cmake --install build
```

### Notes:
It's now completely remade, but some functions in the old/ folder can be useful.
To compile:
```
mkdir build
cd build
cmake ..
make
bin/regev 
```
