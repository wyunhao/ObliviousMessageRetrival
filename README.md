# Whole script needed. Just as notes
```
git clone https://gitlab.com/palisade/palisade-development
cd palisade-development
mkdir build
cd build
sudo apt-get install autoconf
sudo apt-get install cmake
cmake ..
make -j
make install

git clone https://github.com/microsoft/SEAL
cd SEAL
cmake -S . -B build
cmake --build build
sudo cmake --install build

sudo apt-get install libgmp3-dev
wget https://libntl.org/ntl-11.4.3.tar.gz
gunzip ntl-11.4.3.tar.gz
tar xf ntl-11.4.3.tar
cd ntl-11.4.3/src
./configure
make -j
% to check: make check
sudo make install

# clone this repo
mkdir build
cd build
mkdir ../data
mkdir ../data/payloads
cmake ..
make
./regev 
```

# ObliviousMessageRetrival

### Dependency: Palisade, SEAL

```
sudo apt-get install cmake # if no cmake
git clone https://gitlab.com/palisade/palisade-development
mkdir build
cd build
sudo apt-get install autoconf # if no auto conf
cmake ..
make -j
make install
```

```
git clone https://github.com/microsoft/SEAL
cd SEAL
cmake -S . -B build
cmake --build build
sudo cmake --install build
```

```
sudo apt-get install libgmp3-dev # if no gmp
wget https://libntl.org/ntl-11.4.3.tar.gz
gunzip ntl-11.4.3.tar.gz
tar xf ntl-11.4.3.tar
cd ntl-11.4.3/src
./configure
make
make check # if want to check NTL installation
sudo make install
```


### Notes:
It's now completely remade, but some functions in the old/ folder can be useful.
To compile:
```
mkdir build
cd build
mkdir ../data
mkdir ../data/payloads
cmake ..
make
./regev 
```
