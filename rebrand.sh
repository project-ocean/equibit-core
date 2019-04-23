#! /bin/sh

sed -i 's/Equibit/OCEAN/g' configure.ac
sed -i 's/equibit/ocean/g' configure.ac

sed -i 's/Equibit/OCEAN/g' src/Makefile.am
sed -i 's/equibit/ocean/g' src/Makefile.am

find . -name "*.h"   | xargs sed -i 's/EQB/OCN/g'
find . -name "*.cpp" | xargs sed -i 's/EQB/OCN/g'
find . -name "*.h"   | xargs sed -i 's/equibit/ocean/g'
find . -name "*.cpp" | xargs sed -i 's/equibit/ocean/g'
find . -name "*.h"   | xargs sed -i 's/Equibit/OCEAN/g'
find . -name "*.cpp" | xargs sed -i 's/Equibit/OCEAN/g'

find . -name "*.h"   | xargs sed -i 's/OCEAN Group AG/Equibit Group AG/g'
find . -name "*.cpp" | xargs sed -i 's/OCEAN Group AG/Equibit Group AG/g'

sed -i 's/eqb/ocn/g' src/chainparams.cpp

find . -name "*.py"  | xargs sed -i 's/eqbregtest/ocnregtest/g'
find . -name "*.py"  | xargs sed -i 's/EQB/OCN/g'
find . -name "*.py"  | xargs sed -i 's/equibit/ocean/g'
find . -name "*.py"  | xargs sed -i 's/Equibit/OCEAN/g'
find . -name "*.py"  | xargs sed -i 's/OCEAN Group AG/Equibit Group AG/g'

sed -i 's/equibit/ocean/g' eqbtest/util/data/bitcoin-util-test.json
