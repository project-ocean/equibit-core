echo ---------------------------------------------------------
echo This script file creates a linux solution for the project
echo ---------------------------------------------------------


cd ../..

rm -rf .vs.solution

mkdir -p .vs.solution

cd .vs.solution

cmake -DCMAKE_BUILD_TYPE=Release ../.vvvvv

