#!/bin/zsh

##
## zboxapi setup
## API to configure zbox features
##

# Install python pipx for self contained non system python packages
apt install -y pipx

# Ensure pipx is in the PATH
pipx ensurepath

# Reload environment variables
source ~/.zshrc

# Install zboxapi
pipx install zboxapi

##
##  Install Traefik
##

# Variables
URL_TO_TRAEFIK_TAR_GZ="https://github.com/traefik/traefik/releases/download/v2.11.2/traefik_v2.11.2_linux_amd64.tar.gz"
TRAFFIC_FILE_NAME="traefik_v2.11.2_linux_amd64.tar.gz"
TRAFFIC_BINARY_NAME="traefik"
INSTALL_DIR="/usr/local/bin"


# Create a temporary directory
TEMP_DIR=$(mktemp -d)

# Function to clean up temporary directory on exit
cleanup() {
  rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

# Download Traefik tar.gz file to the temporary directory
curl -L -o "$TEMP_DIR/$TRAFFIC_FILE_NAME" $URL_TO_TRAEFIK_TAR_GZ

# Extract the tar.gz file in the temporary directory
tar -xzf "$TEMP_DIR/$TRAFFIC_FILE_NAME" -C "$TEMP_DIR"

# Move the traefik binary to /usr/local/bin
mv "$TEMP_DIR/$TRAFFIC_BINARY_NAME" $INSTALL_DIR

# Set executable permissions on the binary
chmod +x "$INSTALL_DIR/$TRAFFIC_BINARY_NAME"


# Prep Traefik configuration directory
mkdir -vp /etc/traefik/{certificates,dynamic}

#
# Rest will happen with firstboot OVF configuration script
# We require final FQDN to setup certificates + traefik configuration
#
