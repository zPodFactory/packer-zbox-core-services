#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Debian Init script
Based on https://vuptime.io/2017/03/06/vmware-dive-into-ovf-properties/
(password & initial python code for ovfenv properties)
"""

import subprocess
from xml.dom.minidom import parseString
from ipaddress import IPv4Network, ip_network


def appliance_get_ovf_properties():
    """
    Return a dict of OVF properties in the ovfenv
    """
    ovfenv_cmd = "/usr/bin/vmtoolsd --cmd 'info-get guestinfo.ovfEnv'"

    properties = {}
    xml_parts = subprocess.Popen(
        ovfenv_cmd, shell=True, stdout=subprocess.PIPE
    ).stdout.read()
    raw_data = parseString(xml_parts)

    # [0] as we have all the ovfenv sections from the vApp & VMs
    appliancePropertySection = raw_data.getElementsByTagName("PropertySection")[0]

    for property in appliancePropertySection.getElementsByTagName("Property"):
        key, value = [
            property.attributes["oe:key"].value,
            property.attributes["oe:value"].value,
        ]
        properties[key] = value
    return properties


def appliance_create_network_config(properties):
    """
    Create debian /etc/network/interfaces file & restart networking.
    if properties['guestinfo.ipaddress'] exists, setup static network
        -> This assumes all the other ovf variables are correct
    else
        -> This assumes this VM will leverage DHCP
    """

    if properties["guestinfo.ipaddress"]:
        # Extract the network subnet
        network = ip_network(
            f"{properties['guestinfo.ipaddress']}/{properties['guestinfo.netprefix']}",
            strict=False,
        )

        # Calculate all zPod subnets from mgmt subnet
        zpod_global_subnet = f"{network.network_address}/24"
        zpod_subnets = list(
            ip_network(zpod_global_subnet, strict=False).subnets(new_prefix=26)
        )

        network_cmd = """
ip addr flush dev eth0
ip link set dev eth0 down
systemctl stop networking
cat << EOF > /etc/network/interfaces
# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).

# The loopback network interface
auto lo
iface lo inet loopback

# The primary network interface
auto eth0
iface eth0 inet static
    address {ipaddress}/{netprefix}
    gateway {gateway}
    dns-nameservers {dns}

auto eth1
iface eth1 inet manual
    mtu 1700

# Internal non-routed zPod VLANs
# - VLAN 10 (172.16.10.1/24)
# - VLAN 20 (172.16.20.1/24)
# - VLAN 30 (172.16.30.1/24)

auto eth1.10
iface eth1.10 inet static
    address 172.16.10.1/24
    mtu 1700

auto eth1.20
iface eth1.20 inet static
    address 172.16.20.1/24
    mtu 1700

auto eth1.30
iface eth1.30 inet static
    address 172.16.30.1/24
    mtu 1700

# zPod 3 x public /26 routed subnets
# Routed through NSX T1/Static routes

auto eth1.64
iface eth1.64 inet static
    address {gw_64}/{netprefix}
    mtu 1700

auto eth1.128
iface eth1.128 inet static
    mtu 1700
    address {gw_128}/{netprefix}

auto eth1.192
iface eth1.192 inet static
    address {gw_192}/{netprefix}
    mtu 1700


# NO SNAT RFC-1918
post-up iptables -t nat -A POSTROUTING -o eth0 -s 10.0.0.0/8 -j ACCEPT
post-up iptables -t nat -A POSTROUTING -o eth0 -s 172.16.0.0/12 -j ACCEPT
post-up iptables -t nat -A POSTROUTING -o eth0 -s 192.168.0.0/16 -j ACCEPT

# SNAT everything else
post-up iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

EOF
systemctl start networking
""".format(
            ipaddress=properties["guestinfo.ipaddress"],
            gw_64=zpod_subnets[1].network_address + 1,
            gw_128=zpod_subnets[2].network_address + 1,
            gw_192=zpod_subnets[3].network_address + 1,
            netprefix=properties["guestinfo.netprefix"],
            gateway=properties["guestinfo.gateway"],
            dns=properties["guestinfo.dns"],
        )

        subprocess.Popen(network_cmd, shell=True, stdout=subprocess.PIPE).stdout.read()


def appliance_create_hostfile_config(properties):
    """
    Create debian /etc/hosts file for dnsmasq expand-hosts directive.
    """

    if (
        properties["guestinfo.hostname"]
        and properties["guestinfo.ipaddress"]
        and properties["guestinfo.domain"]
    ):
        hostfile_cmd = """cat << EOF > /etc/hosts
127.0.0.1       localhost
{ipaddress}     {hostname}.{domain}    {hostname}
EOF

hostnamectl set-hostname {hostname}.{domain}
        """.format(
            hostname=properties["guestinfo.hostname"],
            ipaddress=properties["guestinfo.ipaddress"],
            domain=properties["guestinfo.domain"],
        )

        subprocess.Popen(hostfile_cmd, shell=True, stdout=subprocess.PIPE).stdout.read()


def appliance_create_dnsmasq_config(properties):
    dnsmasq_conf_cmd = """cat << EOF > /etc/dnsmasq.conf
listen-address=127.0.0.1,{ipaddress}
interface=lo,eth0
bind-interfaces
expand-hosts
bogus-priv
domain={domain}
local=/{domain}/
address=/{domain}/{ipaddress}
server={dns}
server=/in-addr.arpa/{dns}
no-dhcp-interface=lo,eth1,eth2,eth3
dhcp-range={zpodnet}.50,{zpodnet}.60,{netmask},12h
dhcp-option=option:router,{gateway}
dhcp-option=option:ntp-server,{ipaddress}
dhcp-option=option:domain-search,{domain}
EOF
systemctl enable dnsmasq
systemctl stop dnsmasq
systemctl start dnsmasq
""".format(
        ipaddress=properties["guestinfo.ipaddress"],
        netmask=properties["guestinfo.netmask"],
        gateway=properties["guestinfo.gateway"],
        zpodnet=properties["guestinfo.zpodnet"],
        domain=properties["guestinfo.domain"],
        dns=properties["guestinfo.dns"],
    )

    subprocess.Popen(dnsmasq_conf_cmd, shell=True, stdout=subprocess.PIPE).stdout.read()


def appliance_create_ntp_config(properties):
    ntp_cmd = """cat << EOF > /etc/ntp.conf
tinker panic 0
driftfile /var/lib/ntp/ntp.drift
filegen clockstats file clockstats type day enable
filegen loopstats file loopstats type day enable
filegen peerstats file peerstats type day enable
pool 0.debian.pool.ntp.org iburst
pool 1.debian.pool.ntp.org iburst
pool 2.debian.pool.ntp.org iburst
pool 3.debian.pool.ntp.org iburst
restrict {zpodnet}.0 mask {netmask} nomodify notrap
restrict 127.0.0.1
restrict -4 default kod notrap nomodify nopeer noquery limited
restrict -6 default kod notrap nomodify nopeer noquery limited
restrict source notrap nomodify noquery
statistics loopstats peerstats clockstats
EOF
systemctl enable ntp
systemctl stop ntp
systemctl start ntp
""".format(
        zpodnet=properties["guestinfo.zpodnet"], netmask=properties["guestinfo.netmask"]
    )

    subprocess.Popen(ntp_cmd, shell=True, stdout=subprocess.PIPE).stdout.read()


def appliance_create_nfs_config(properties):
    """
    Create a NFS export from any new added storage disk
    """

    disks = subprocess.run(
        ["lsblk", "-dn", "-o", "NAME", "-e", "11"], capture_output=True, text=True
    ).stdout.split()
    for disk in disks:
        result = subprocess.run(["blkid", f"/dev/{disk}"], capture_output=True)
        if result.returncode != 0:
            fdisk_cmd = """
echo 'g\nn\n\n\n\nw\n' | fdisk /dev/{disk}
mkfs.ext4 /dev/{disk}1
sync
sleep 2
UUID=$(/usr/bin/lsblk -o UUID /dev/{disk}1 | grep -v UUID)
echo "UUID=$UUID"
echo "UUID=$UUID" >> /etc/uuid.storage
sleep 30
echo "UUID=$UUID /FILER/STORAGE01 ext4 defaults 1 1" >> /etc/fstab
mkdir -vp /FILER/STORAGE01
mount -a
mkdir -vp /FILER/STORAGE01/NFS-01
mkdir -vp /FILER/STORAGE01/NFS-VCD
mkdir -vp /FILER/STORAGE01/VCF-BACKUPS
chmod -R 777 /FILER
echo "/FILER/STORAGE01/NFS-01     {zpodsubnet}(rw,no_subtree_check)" > /etc/exports
echo "/FILER/STORAGE01/NFS-VCD    {zpodsubnet}(rw,no_subtree_check,no_root_squash)" >> /etc/exports
sed -i '/^RPCMOUNTDOPTS.*$/s/^/#/' /etc/default/nfs-kernel-server
systemctl enable nfs-server
systemctl stop nfs-server
systemctl start nfs-server
            """.format(disk=disk, zpodsubnet=properties["guestinfo.zpodsubnet"])
            result = subprocess.Popen(
                fdisk_cmd, shell=True, stdout=subprocess.PIPE
            ).stdout.read()


def appliance_update_credentials(properties):
    """
    Update Appliance root password & SSH KEY
    """

    if properties["guestinfo.password"]:
        password_cmd = """echo root:{password} | chpasswd""".format(
            password=properties["guestinfo.password"]
        )
        subprocess.Popen(password_cmd, shell=True, stdout=subprocess.PIPE).stdout.read()

    if properties["guestinfo.sshkey"]:
        sshkey_cmd = """echo '{sshkey}' >> /root/.ssh/authorized_keys""".format(
            sshkey=properties["guestinfo.sshkey"]
        )
        subprocess.Popen(sshkey_cmd, shell=True, stdout=subprocess.PIPE).stdout.read()


def appliance_generate_certificates(properties):
    """
    Generate SSL certificates for Traefik/zboxapi
    """

    certificates_cmd = """openssl req -x509 -newkey rsa:2048 -days 3560 -nodes \
 -keyout /etc/traefik/certificates/cert.key \
 -out /etc/traefik/certificates/cert.crt \
 -subj "/C=US/O=zPodFactory/CN=zbox.{domain}" -addext "subjectAltName = DNS:zbox.{domain}"
""".format(domain=properties["guestinfo.domain"])

    subprocess.Popen(certificates_cmd, shell=True, stdout=subprocess.PIPE).stdout.read()


def appliance_generate_traefik_config(properties):
    """
    Generate Traefik configuration
    """

    traefik_dynamic_internal_cmd = """cat << EOF > /etc/traefik/dynamic/internal.yml
http:
  routers:
    dashboard-router:
      rule: "Host(\`zbox.{domain}\`) && PathPrefix(\`/dashboard\`) || PathPrefix(\`/api\`)"
      entryPoints: ["websecure"]
      service: api@internal
      tls: true
EOF
""".format(domain=properties["guestinfo.domain"])

    subprocess.Popen(
        traefik_dynamic_internal_cmd, shell=True, stdout=subprocess.PIPE
    ).stdout.read()


def appliance_generate_zboxapi_config(properties):
    """
    Generate zboxapi configuration
    """

    traefik_dynamic_zboxapi_cmd = """cat << EOF > /etc/traefik/dynamic/zboxapi.yml
http:
  routers:
    zboxapi-router:
      rule: "Host(\`zbox.{domain}\`) && PathPrefix(\`/zboxapi\`)"
      entryPoints: ["websecure"]
      middlewares:
        - "prefix-api@file"
      service: zboxapi
      tls: true

  services:
    zboxapi:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:8000"

  middlewares:
    prefix-api:
      stripPrefix:
        prefixes:
          - "/zboxapi"
        forceSlash: false
EOF""".format(domain=properties["guestinfo.domain"])

    subprocess.Popen(
        traefik_dynamic_zboxapi_cmd, shell=True, stdout=subprocess.PIPE
    ).stdout.read()


def appliance_setup_zboxapi(properties):
    """
    Setup zBoxAPI
    """

    zboxapi_cmd = """# Enable zBoxAPI
systemctl daemon-reload
systemctl enable zboxapi
systemctl enable traefik
systemctl start zboxapi
systemctl start traefik
"""

    subprocess.Popen(zboxapi_cmd, shell=True, stdout=subprocess.PIPE).stdout.read()


# Appliance configuration flow.
# Fetch properties from OVF Environment
# 1. Setup Appliance Networking
# 2. Setup /etc/hosts & /etc/hostname file
# 3. Setup dnsmasq configuration
# 4. Setup ntp configuration
# 5. Setup NFS configuration
# 6. Update Root password & SSH Key
# 7. Generate Certificates for Traefik/zBoxAPI
# 8. Generate Traefik configuration
# 9. Generate zBoxAPI configuration
# 10. Setup zBoxAPI
#


properties = appliance_get_ovf_properties()
# extrapolate some required network values...
properties["guestinfo.zpodnet"] = ".".join(
    properties["guestinfo.ipaddress"].split(".")[0:3]
)

zpodsubnet = properties["guestinfo.netmask"] = IPv4Network(
    "{zpodnet}.0/{netprefix}".format(
        zpodnet=properties["guestinfo.zpodnet"],
        netprefix=properties["guestinfo.netprefix"],
    )
)

properties["guestinfo.zpodsubnet"] = zpodsubnet
properties["guestinfo.netmask"] = zpodsubnet.netmask

appliance_create_network_config(properties)
appliance_create_hostfile_config(properties)
appliance_create_dnsmasq_config(properties)
appliance_create_ntp_config(properties)
appliance_create_nfs_config(properties)
appliance_update_credentials(properties)
appliance_generate_certificates(properties)
appliance_generate_traefik_config(properties)
appliance_generate_zboxapi_config(properties)
appliance_setup_zboxapi(properties)
