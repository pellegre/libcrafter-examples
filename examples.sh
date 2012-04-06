# Script to generate examples.tar.gz with the examples codes
#!/bin/bash

EXAMPLE_FOLDER="examples"

source folders.sh

# Remove the Example folder
rm -rf ${EXAMPLE_FOLDER}
rm -f ${EXAMPLE_FOLDER}.tar.gz

# Create the folder
mkdir ${EXAMPLE_FOLDER}

# Initialize counter
counter=1

# Iterate the folders
for folder in ${FOLDERS} ; do
  mkdir ${EXAMPLE_FOLDER}/${counter}.${folder}
  cp ${folder}/main.cpp ${EXAMPLE_FOLDER}/${counter}.${folder}/
  let counter=${counter}+1
done

# Create a compressed file
tar cvfz ${EXAMPLE_FOLDER}.tar.gz ${EXAMPLE_FOLDER}

