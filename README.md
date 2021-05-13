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

# Notes:
pk_enc_utils.h includes the in-progress test of packing, but will be held for now. <br />
Other files' functions are mostly finished and tested. Some may need modifications during integration test. <br />
Next steps: finish equation solving and the multiplications in the middle steps.
