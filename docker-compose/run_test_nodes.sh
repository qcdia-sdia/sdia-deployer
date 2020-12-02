#!/bin/bash

apt update -y
apt install openssh-server sudo -y
service ssh start

getent passwd vm_user > /dev/null 2&>1

if [ $? -eq 0 ]; then
    echo "user exists"
else
    useradd vm_user -s /bin/bash -m
    echo "vm_user ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
fi


FILE=/home/vm_user/.ssh/authorized_keys
if [ -f "$FILE" ]; then
    echo "$FILE exists."
else
    mkdir -p /home/vm_user/.ssh && touch /home/vm_user/.ssh/authorized_keys
    echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC/Eeau4FJz3q/jWUUIEJj9mgC5nttsry2XbVQltZW1CW+3NQo3LRQ8xRageFCY7ud6T8ExgXUnajKj2Gl28WXB9mhnHSLVEeS9Ye1R+M+Cp9gkQviTO1ni+QeG+imSrjFJI+UfyqlIO6g4Grhmp6ugnpGxk3tIb6jwSre3RM68KcZA1ZBfGHDDBVkEhoEEfdt0ulj6F2O+Rf1SEOrL4ixChloKO/YtBcttPMllCdF1b+VFhrY1Yf0mahjZq5KhHiuSwzloBIrMMb2uryUxQq4I+kXHhQrgAflQaILgMZH8n0flKlyXaI93G6qY/b9auGybDNd4ROjQxp/F/trYF7i9Z6Gb71iisud7BPsuqQkP8LLpSaBNG84l5xJj1G0wRrNBEVJANbgabc7fb/0xsZjmKHxzuwxPrBBBwoYoroGwJsb4D03A3nC2WqF8UGinjK0RSpjMONLrqjN1Y11KuZnRGPYqiReHeXbUpl0Fk3r3uhawB3+UvSTbjSXw5klJlUX6tvD0ZMbkzfANAbtbPKwUzNCA8OXiVX/SfHWiHHO90cDZsTJZQKOGXvhaoiqUehtMSBHbKQDMYcTxdNPHW1DnjkcM55eyapxaPoumEnC82iCXl5ndxZVXkq56RxiH0sDGRRDKOx8csbD84l+FG6WfDds3fThMNoU4eGUrXUPMVw== vm_user@host' >> /home/vm_user/.ssh/authorized_keys
fi

cat /home/vm_user/.ssh/authorized_keys

tail -f /dev/null
