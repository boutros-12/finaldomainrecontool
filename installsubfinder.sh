#!/bin/bash
set -e

SUBFINDER_VERSION="2.8.0"

# Create bin folder
mkdir -p bin

# Download Subfinder release (Linux amd64)
curl -L -o subfinder-linux-amd64.tar.gz https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder-linux-amd64.tar.gz

# Extract to ./bin
tar -xzf subfinder-linux-amd64.tar.gz -C bin

# Make executable
chmod +x bin/subfinder

# Remove tarball
rm subfinder-linux-amd64.tar.gz

echo "Subfinder installed at ./bin/subfinder"
