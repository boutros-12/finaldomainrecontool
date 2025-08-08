#!/bin/bash
set -e

SUBFINDER_VERSION="2.8.0"

# Create bin directory if not present
mkdir -p bin

# Download the Subfinder Linux AMD64 zip archive from the official GitHub releases
curl -L -o subfinder-linux-amd64.zip https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder-linux-amd64.zip

# Unzip the downloaded zip file into ./bin directory
unzip -o subfinder-linux-amd64.zip -d bin

# Make the Subfinder binary executable
chmod +x bin/subfinder

# Remove the zip archive to save space
rm subfinder-linux-amd64.zip

echo "Subfinder installed at ./bin/subfinder"
