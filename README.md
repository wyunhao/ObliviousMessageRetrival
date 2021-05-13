# ObliviousMessageRetrival

# Dependency: TFHE & MSSeal

```
git clone https://github.com/tfhe/tfhe
cd tfhe
mkdir build
cd build
cmake ../src -DENABLE_TESTS=on -DENABLE_FFTW=on -DCMAKE_BUILD_TYPE=debug
make
```

```
git clone https://github.com/microsoft/SEAL
cd SEAL
cmake -S . -B build
cmake --build build
sudo cmake --install build
```
