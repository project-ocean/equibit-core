#! /bin/sh

find . -name "*.vcxproj*" | xargs sed -i 's/equibit/ocean/g'
rename 's/equibit/ocean/' *
rename 's/equibit/ocean/' */*
