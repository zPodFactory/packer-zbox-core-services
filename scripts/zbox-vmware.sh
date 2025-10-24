#!/bin/bash -eux

##
## VMware related stuff
## Install VMware related tools
##

echo '> Installing VMware Software...'

apt-get install -y \
  open-vm-tools

# Disable VMware guest tools customization of the VM
# OVF Properties / cloud-init configuration can be used.
cat >> /etc/vmware-tools/tools.conf << 'EOF'
[deployPkg]
enable-customization=false
EOF


# Install govc from github
wget -qO- https://github.com/vmware/govmomi/releases/download/v0.51.0/govc_Linux_x86_64.tar.gz \
  | tar -xzf - -C /usr/local/bin govc \
  && chmod +x /usr/local/bin/govc \
  && chown root:root /usr/local/bin/govc

echo '> Done'