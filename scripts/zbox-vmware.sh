#!/bin/bash -eux

##
## VMware related stuff
## Install VMware related tools
##

echo '> Installing VMware Software...'

apt-get install -y \
  open-vm-tools


# Install govc from github
wget -qO- https://github.com/vmware/govmomi/releases/download/v0.51.0/govc_Linux_x86_64.tar.gz \
  | tar -xzf - -C /usr/local/bin govc \
  && chmod +x /usr/local/bin/govc \
  && chown root:root /usr/local/bin/govc

echo '> Done'