#! /bin/bash
set -e
set -x

# clean old data
rm /etc/apt/keyrings/kubernetes-apt-keyring.gpg || true
rm /etc/apt/sources.list.d/kubernetes.list || true
rm /usr/share/keyrings/kubernetes-archive-keyring.gpg || true

sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates curl
# 注意 如果用curl，必须再次确认环境变量http_proxy是否设置代理地址
#sudo curl -fsSLo /usr/share/keyrings/kubernetes-archive-keyring.gpg https://packages.cloud.google.com/apt/doc/apt-key.gpg
mkdir -p /usr/share/keyrings
wget  https://packages.cloud.google.com/apt/doc/apt-key.gpg -O /usr/share/keyrings/kubernetes-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/kubernetes-archive-keyring.gpg] https://apt.kubernetes.io/ kubernetes-xenial main" | sudo tee /etc/apt/sources.list.d/kubernetes.list
sudo apt-get update
sudo apt-get install -y kubelet=1.18.0-00 kubeadm=1.18.0-00 kubectl=1.18.0-00
sudo apt-mark hold kubelet kubeadm kubectl
