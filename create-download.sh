#!/bin/bash

# Create a ZIP file with just the key code files
echo "Creating ZIP file of the core codebase..."

# Create a directory to store the files for ZIP
mkdir -p project_files

# Copy only the project-specific directories and files
cp -r client project_files/
cp -r db project_files/
cp -r server project_files/
cp *.js *.ts *.json project_files/ 2>/dev/null || true

# Create the ZIP file
cd project_files
zip -r ../codebase.zip .
cd ..

echo "ZIP file created: codebase.zip"
echo "You can download this file from the Files panel in Replit."