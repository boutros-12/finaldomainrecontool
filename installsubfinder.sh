#!/bin/bash
set -e

SUBFINDER_VERSION="2.8.0"

# Create bin directory if not present
mkdir -p bin

echo "Downloading Subfinder v${SUBFINDER_VERSION}..."
curl -L -o subfinder-linux-amd64.zip https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder-linux-amd64.zip

echo "Downloaded file details:"
ls -lh subfinder-linux-amd64.zip
file subfinder-linux-amd64.zip

unzip -o subfinder-linux-amd64.zip -d bin

chmod +x bin/subfinder

rm subfinder-linux-amd64.zip

echo "Subfinder installed at ./bin/subfinder"
