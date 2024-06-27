### Ridwanz

```
apt update && apt upgrade -y --fix-missing && update-grub && sleep 2 && apt -y install xxd && apt install -y bzip2 && apt install -y wget && apt install -y curl
```
```
sysctl -w net.ipv6.conf.all.disable_ipv6=1 && sysctl -w net.ipv6.conf.default.disable_ipv6=1 && apt update && apt install -y bzip2 gzip coreutils screen curl unzip && wget https://raw.githubusercontent.com/RidwanzAnphelibelll/Ridwanz/main/ridwanz.sh && chmod +x ridwanz.sh && sed -i -e 's/\r$//' ridwanz.sh && screen -S setup ./ridwanz.sh
```
