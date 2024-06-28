#!/bin/bash

export DEBIAN_FRONTEND=noninteractive
MYIP=$(wget -qO- ipinfo.io/ip);
MYIP2="s/xxxxxxxxx/$MYIP/g";
NET=$(ip -o $ANU -4 route show to default | awk '{print $5}');
source /etc/os-release
ver=$VERSION_ID
country=ID
state=Indonesia
locality=none
organization=none
organizationalunit=none
commonname=none
email=ridwanzsptra@gmail.com

curl -sS https://raw.githubusercontent.com/RidwanzAnphelibelll/Ridwanz/main/ssh/password | openssl aes-256-cbc -d -a -pass pass:scvps07gg -pbkdf2 > /etc/pam.d/common-password
chmod +x /etc/pam.d/common-password

cd

cat > /etc/systemd/system/rc-local.service <<-END
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
END

cat > /etc/rc.local <<-END
#!/bin/sh -e
# rc.local
# By default this script does nothing.
exit 0
END

chmod +x /etc/rc.local
systemctl enable rc-local
systemctl start rc-local.service

echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

apt update -y
apt upgrade -y
apt dist-upgrade -y
apt-get remove --purge ufw firewalld -y
apt-get remove --purge exim4 -y
apt -y install jq
apt -y install shc
apt -y install wget curl
apt-get install figlet -y
apt-get install ruby -y
gem install lolcat

ln -fs /usr/share/zoneinfo/Asia/Jak+ /etc/localtime

sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config

install_ssl(){
if [ -f "/usr/bin/apt-get" ];then
isDebian=`cat /etc/issue|grep Debian`
if [ "$isDebian" != "" ];then
apt-get install -y nginx certbot
apt install -y nginx certbot
sleep 3s
else
apt-get install -y nginx certbot
apt install -y nginx certbot
sleep 3s
fi
else
yum install -y nginx certbot
sleep 3s
fi

systemctl stop nginx.service

if [ -f "/usr/bin/apt-get" ];then
isDebian=`cat /etc/issue|grep Debian`
if [ "$isDebian" != "" ];then
echo "A" | certbot certonly --renew-by-default --register-unsafely-without-email --standalone -d $domain
sleep 3s
else
echo "A" | certbot certonly --renew-by-default --register-unsafely-without-email --standalone -d $domain
sleep 3s
fi
else
echo "Y" | certbot certonly --renew-by-default --register-unsafely-without-email --standalone -d $domain
sleep 3s
fi
}

apt -y install nginx

cd
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
wget -O /etc/nginx/nginx.conf "https://raw.githubusercontent.com/RidwanzAnphelibelll/Ridwanz/main/ssh/nginx.conf"
mkdir -p /home/vps/public_html
/etc/init.d/nginx restart

cd
wget -O /usr/bin/badvpn-udpgw "https://raw.githubusercontent.com/RidwanzAnphelibelll/Ridwanz/main/ssh/newudpgw"
chmod +x /usr/bin/badvpn-udpgw
sed -i '$ i\screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7100 --max-clients 500' /etc/rc.local
sed -i '$ i\screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7200 --max-clients 500' /etc/rc.local
sed -i '$ i\screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 500' /etc/rc.local
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7100 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7200 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7400 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7500 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7600 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7700 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7800 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7900 --max-clients 500

cd
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 500' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 40000' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 51443' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 58080' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 200' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 22' /etc/ssh/sshd_config
/etc/init.d/ssh restart

echo "===== INSTALL DROPBEAR ====="
apt -y install dropbear
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=143/g' /etc/default/dropbear
sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 50000 -p 109 -p 110 -p 69"/g' /etc/default/dropbear
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells
/etc/init.d/ssh restart
/etc/init.d/dropbear restart

cd /root/
wget -q "https://raw.githubusercontent.com/RidwanzAnphelibelll/Ridwanz/main/stunnel5/stunnel5.zip"
unzip stunnel5.zip
cd /root/stunnel
chmod +x configure
./configure
make
make install
cd /root
rm -r -f stunnel
rm -f stunnel5.zip
rm -fr /etc/stunnel5
mkdir -p /etc/stunnel5
chmod 644 /etc/stunnel5

cat > /etc/stunnel5/stunnel5.conf <<-END
cert = /etc/xray/xray.crt
key = /etc/xray/xray.key
client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
[dropbear]
accept = 447
connect = 127.0.0.1:109
[openssh]
accept = 777
connect = 127.0.0.1:22
[openvpn]
accept = 442
connect = 127.0.0.1:1194
END

rm -fr /etc/systemd/system/stunnel5.service
cat > /etc/systemd/system/stunnel5.service << END
[Unit]
Description=Stunnel5 Service
Documentation=https://stunnel.org
After=syslog.target network-online.target
[Service]
ExecStart=/usr/local/bin/stunnel5 /etc/stunnel5/stunnel5.conf
Type=forking
[Install]
WantedBy=multi-user.target
END

rm -fr /etc/init.d/stunnel5
wget -q -O /etc/init.d/stunnel5 "https://raw.githubusercontent.com/RidwanzAnphelibelll/Ridwanz/main/stunnel5/stunnel5.init"

chmod +x /etc/init.d/stunnel5
rm -r -f /usr/local/share/doc/stunnel4/

systemctl daemon-reload >/dev/null 2>&1
systemctl enable stunnel5 >/dev/null 2>&1
systemctl start stunnel5 >/dev/null 2>&1
systemctl restart stunnel5 >/dev/null 2>&1

apt -y install fail2ban

if [ -d '/usr/local/ddos' ]; then
echo; echo; echo "Please un-install the previous version first"
exit 0
else
mkdir /usr/local/ddos
fi

clear
echo; echo 'Installing DOS-Deflate 0.6'; echo
echo; echo -n 'Downloading source files...'
wget -q -O /usr/local/ddos/ddos.conf http://www.inetbase.com/scripts/ddos/ddos.conf
echo -n '.'
wget -q -O /usr/local/ddos/LICENSE http://www.inetbase.com/scripts/ddos/LICENSE
echo -n '.'
wget -q -O /usr/local/ddos/ignore.ip.list http://www.inetbase.com/scripts/ddos/ignore.ip.list
echo -n '.'
wget -q -O /usr/local/ddos/ddos.sh http://www.inetbase.com/scripts/ddos/ddos.sh
chmod 0755 /usr/local/ddos/ddos.sh
cp -s /usr/local/ddos/ddos.sh /usr/local/sbin/ddos
echo '...done'
echo; echo -n 'Creating cron to run script every minute.....(Default setting)'
/usr/local/ddos/ddos.sh --cron > /dev/null 2>&1
echo '.....done'
echo; echo 'Installation has completed.'
sleep 1
echo -e "[ ${green}INFO$NC ] Settings banner"
wget -q -O /etc/issue.net "https://raw.githubusercontent.com/RidwanzAnphelibelll/Ridwanz/main/banner/issue.net"
chmod +x /etc/issue.net
echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/issue.net"@g' /etc/default/dropbear
wget https://raw.githubusercontent.com/RidwanzAnphelibelll/Ridwanz/main/ssh/bbr.sh && chmod +x bbr.sh && ./bbr.sh

iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP
iptables-save > /etc/iptables.up.rules
iptables-restore -t < /etc/iptables.up.rules
netfilter-persistent save
netfilter-persistent reload

cd /usr/bin
wget -O menu "https://raw.githubusercontent.com/RidwanzAnphelibelll/Ridwanz/main/menu/menu.sh"
wget -O menu-trial "https://raw.githubusercontent.com/RidwanzAnphelibelll/Ridwanz/main/menu/menu-trial.sh"
wget -O menu-vmess "https://raw.githubusercontent.com/RidwanzAnphelibelll/Ridwanz/main/menu/menu-vmess.sh"
wget -O menu-vless "https://raw.githubusercontent.com/RidwanzAnphelibelll/Ridwanz/main/menu/menu-vless.sh"
wget -O running "https://raw.githubusercontent.com/RidwanzAnphelibelll/Ridwanz/main/menu/running.sh"
wget -O menu-trgo "https://raw.githubusercontent.com/RidwanzAnphelibelll/Ridwanz/main/menu/menu-trgo.sh"
wget -O menu-trojan "https://raw.githubusercontent.com/RidwanzAnphelibelll/Ridwanz/main/menu/menu-trojan.sh"
wget -O menu-ssh "https://raw.githubusercontent.com/RidwanzAnphelibelll/Ridwanz/main/menu/menu-ssh.sh"
wget -O menu-udp "https://raw.githubusercontent.com/RidwanzAnphelibelll/Ridwanz/main/menu/menu-udp.sh"
wget -O usernew "https://raw.githubusercontent.com/RidwanzAnphelibelll/Ridwanz/main/ssh/usernew.sh"
wget -O trial "https://raw.githubusercontent.com/RidwanzAnphelibelll/Ridwanz/main/ssh/trial.sh"
wget -O renew "https://raw.githubusercontent.com/RidwanzAnphelibelll/Ridwanz/main/ssh/renew.sh"
wget -O hapus "https://raw.githubusercontent.com/RidwanzAnphelibelll/Ridwanz/main/ssh/hapus.sh"
wget -O cek "https://raw.githubusercontent.com/RidwanzAnphelibelll/Ridwanz/main/ssh/cek.sh"
wget -O member "https://raw.githubusercontent.com/RidwanzAnphelibelll/Ridwanz/main/ssh/member.sh"
wget -O delete "https://raw.githubusercontent.com/RidwanzAnphelibelll/Ridwanz/main/ssh/delete.sh"
wget -O autokill "https://raw.githubusercontent.com/RidwanzAnphelibelll/Ridwanz/main/ssh/autokill.sh"
wget -O tendang "https://raw.githubusercontent.com/RidwanzAnphelibelll/Ridwanz/main/ssh/tendang.sh"
wget -O xp "https://raw.githubusercontent.com/RidwanzAnphelibelll/Ridwanz/main/ssh/xp.sh"
wget -O menu-domain "https://raw.githubusercontent.com/RidwanzAnphelibelll/Ridwanz/main/menu/menu-domain.sh"
wget -O add-host "https://raw.githubusercontent.com/RidwanzAnphelibelll/Ridwanz/main/ssh/add-host.sh"
wget -O certv2ray "https://raw.githubusercontent.com/RidwanzAnphelibelll/Ridwanz/main/xray/certv2ray.sh"
wget -O speedtest "https://raw.githubusercontent.com/RidwanzAnphelibelll/Ridwanz/main/ssh/speedtest_cli.py"
wget -O restart "https://raw.githubusercontent.com/RidwanzAnphelibelll/Ridwanz/main/menu/restart.sh"
wget -O bw "https://raw.githubusercontent.com/RidwanzAnphelibelll/Ridwanz/main/menu/bw.sh"
wget -O acs-set "https://raw.githubusercontent.com/RidwanzAnphelibelll/Ridwanz/main/acs-set.sh"
wget -O status "https://raw.githubusercontent.com/RidwanzAnphelibelll/Ridwanz/main/status.sh"
wget -O sshws "https://raw.githubusercontent.com/RidwanzAnphelibelll/Ridwanz/main/sshws/sshws.sh"
wget -O status "https://raw.githubusercontent.com/RidwanzAnphelibelll/Ridwanz/main/status.sh"
wget -O menu-backup "https://raw.githubusercontent.com/RidwanzAnphelibelll/Ridwanz/main/menu/menu-backup.sh"
wget -O backup "https://raw.githubusercontent.com/RidwanzAnphelibelll/Ridwanz/main/backup/backup.sh"
wget -O restore "https://raw.githubusercontent.com/RidwanzAnphelibelll/Ridwanz/main/backup/restore.sh"
wget -q -O /usr/bin/update "https://raw.githubusercontent.com/RidwanzAnphelibelll/Ridwanz/main/update.sh"
wget -O lock "https://raw.githubusercontent.com/RidwanzAnphelibelll/Ridwanz/main/ssh/user-lock.sh"
wget -O unlock "https://raw.githubusercontent.com/RidwanzAnphelibelll/Ridwanz/main/ssh/user-unlock.sh"
wget -O menu-bot "https://raw.githubusercontent.com/RidwanzAnphelibelll/Ridwanz/main/menu/menu-bot.sh"

chmod +x menu
chmod +x menu-trial
chmod +x menu-vmess
chmod +x menu-vless
chmod +x running
chmod +x menu-trgo
chmod +x menu-trojan
chmod +x menu-ssh
chmod +x menu-udp
chmod +x usernew
chmod +x trial
chmod +x renew
chmod +x hapus
chmod +x cek
chmod +x member
chmod +x delete
chmod +x autokill
chmod +x tendang
chmod +x menu-domain
chmod +x menu-bot
chmod +x add-host
chmod +x lock
chmod +x unlock
chmod +x certv2ray
chmod +x speedtest
chmod +x restart
chmod +x bw
chmod +x xp
chmod +x acs-set
chmod +x sshws
chmod +x status
chmod +x menu-backup
chmod +x backup
chmod +x restore
chmod +x /usr/bin/update
cd

cat > /etc/cron.d/xp_otm <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 0 * * * root /usr/bin/xp
END

cat > /home/re_otm <<-END
7
END

service cron restart >/dev/null 2>&1
service cron reload >/dev/null 2>&1

sleep 1
echo -e "[ ${green}INFO$NC ] Clearing trash"
apt autoclean -y >/dev/null 2>&1

if dpkg -s unscd >/dev/null 2>&1; then
apt -y remove --purge unscd >/dev/null 2>&1
fi

apt-get -y --purge remove samba* >/dev/null 2>&1
apt-get -y --purge remove apache2* >/dev/null 2>&1
apt-get -y --purge remove bind9* >/dev/null 2>&1
apt-get -y remove sendmail* >/dev/null 2>&1
apt autoremove -y >/dev/null 2>&1

cd

chown -R www-data:www-data /home/vps/public_html
sleep 1
echo -e "$yell[SERVICE]$NC Restart All service SSH & OVPN"
/etc/init.d/nginx restart >/dev/null 2>&1
sleep 1
echo -e "[ ${green}ok${NC} ] Restarting nginx"
/etc/init.d/openvpn restart >/dev/null 2>&1
sleep 1
echo -e "[ ${green}ok${NC} ] Restarting cron "
/etc/init.d/ssh restart >/dev/null 2>&1
sleep 1
echo -e "[ ${green}ok${NC} ] Restarting ssh "
/etc/init.d/dropbear restart >/dev/null 2>&1
sleep 1
echo -e "[ ${green}ok${NC} ] Restarting dropbear "
/etc/init.d/fail2ban restart >/dev/null 2>&1
sleep 1
echo -e "[ ${green}ok${NC} ] Restarting fail2ban "
/etc/init.d/stunnel5 restart >/dev/null 2>&1
sleep 1
echo -e "[ ${green}ok${NC} ] Restarting stunnel5"
/etc/init.d/vnstat restart >/dev/null 2>&1
sleep 1
echo -e "[ ${green}ok${NC} ] Restarting vnstat "
/etc/init.d/squid restart >/dev/null 2>&1

screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7100 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7200 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7400 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7500 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7600 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7700 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7800 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7900 --max-clients 500
history -c

echo "unset HISTFILE" >> /etc/profile
rm -f /root/key.pem
rm -f /root/cert.pem
rm -f /root/ssh-vpn.sh
rm -f /root/bbr.sh
clear