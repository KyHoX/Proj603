#!/bin/bash

# Update the package list
echo "Updating package list..."
sudo apt update

# Install Nmap
echo "Installing Nmap..."
sudo apt install -y nmap

# Check if Python is installed, if not, install Python
if ! command -v python3 &> /dev/null
then
    echo "Python3 not found, installing Python3..."
    sudo apt install -y python3
else
    echo "Python3 is already installed."
fi

# Install pip for Python package management
if ! command -v pip3 &> /dev/null
then
    echo "pip3 not found, installing pip3..."
    sudo apt install -y python3-pip
else
    echo "pip3 is already installed."
fi

echo "Nmap and Python setup completed successfully."
