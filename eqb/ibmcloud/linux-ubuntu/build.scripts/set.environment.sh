#!/bin/bash

script_name=$(realpath "$BASH_SOURCE")
script_folder=$(dirname "$script_name")
<<<<<<< HEAD
source_folder=$(realpath "$script_folder/../../../..")
=======
source_folder=$(realpath "$script_folder/../../..")
>>>>>>> issues/#18-sha3
thridparty_folder=$(realpath "$source_folder/../thirdparty")
berkley_folder="$thridparty_folder/db4"

echo "*** Set environment variables ***"
echo "script_name      " = "$script_name"
echo "script_folder    " = "$script_folder"
echo "source_folder    " = "$source_folder"
echo "thridparty_folder" = "$thridparty_folder"
echo "berkley_folder   " = "$berkley_folder"
echo ""
