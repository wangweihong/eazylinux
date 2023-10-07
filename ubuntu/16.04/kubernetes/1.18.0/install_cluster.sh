#!/usr/bin/env bash
set -e
set -x

KUBEVERSION=1.18.0-00

cat > /usr/bin/kubelet-pre-start.sh <<END
#!/bin/bash
# Open ipvs
modprobe -- ip_vs
modprobe -- ip_vs_rr
modprobe -- ip_vs_wrr
modprobe -- ip_vs_sh
if [[ $(uname -r |cut -d . -f1) -ge 4 && $(uname -r |cut -d . -f2) -ge 19 ]]; then
  modprobe -- nf_conntrack
else
  modprobe -- nf_conntrack_ipv4
fi

cat <<EOF >  /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
EOF
sysctl --system
sysctl -w net.ipv4.ip_forward=1
# systemctl stop firewalld && systemctl disable firewalld
#  注意, swapoff -a不完全可行, 如果/etc/fstab存在swap分区的配置的话, 即使执行了swapoff -a, 间隔一段时间swap又会启动
#  通过cat /proc/swaps 确认swap是否启动
swapoff -a
setenforce 0
exit 0
END

chmod +x /usr/bin/kubelet-pre-start.sh

cat > /lib/systemd/system/kubelet.service <<EOF
[Unit]
Description=kubelet: The Kubernetes Node Agent
Documentation=http://kubernetes.io/docs/

[Service]
ExecStart=/usr/bin/kubelet $KUBELET_KUBECONFIG_ARGS $KUBELET_CONFIG_ARGS $KUBELET_KUBEADM_ARGS $KUBELET_EXTRA_ARGS
ExecStartPre=/usr/bin/kubelet-pre-start.sh
Restart=always
StartLimitInterval=0
RestartSec=10

[Install]
WantedBy=multi-user.target

EOF

cat > /etc/docker/daemon.json <<EOF
{
        "max-concurrent-downloads": 10,
        "exec-opts": ["native.cgroupdriver=systemd"],
        "log-driver": "json-file",
        "log-opts": {
                "max-size": "100m"
        },
        "storage-driver": "overlay2"
}
EOF


systemctl daemon-reload
systemctl restart kubelet
systemctl restart docker

localIP=`/sbin/ifconfig ens33 | awk -F ' *|:' '/inet addr/{print $4}'`

# make sure has set proxy
kubeadm config images pull
kubeadm init --apiserver-advertise-address=$localIP --kubernetes-version=$KUBEVERSION

# 安装网络插件
kubectl apply -f https://docs.projectcalico.org/archive/v3.14/manifests/calico.yaml
kubectl taint nodes --all node-role.kubernetes.io/master- # 如果是单点测试环境，则移除master节点上的taint