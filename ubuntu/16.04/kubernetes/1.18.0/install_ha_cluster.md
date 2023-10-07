# 原理
 从kubeadm设计的角度，节点分为Master0节点和其他节点（其他master节点masterN或者其他工作节点）。
 master0部署成功后会将kubelet配置上传到apierver的configmap中/证书配置会AES加密后上传到secret中。
 * 如果其他节点是master节点， 则会通过certificate key解密secret得到证书后，保存到当前节点上/etc/kubernetes/pki目录中。下载kubelet配置保存到/var/lib/kubelet中
 * 如果是工作节点，则直接下载kubelet配置启动kubelt配置

# 部署建议补充
* 建议harbor仓库使用域名。否则一旦变更了harbor ip 地址，会导致daemonSet资源新节点的副本无法正常拉取镜像。
* 注意各节点提前配置好dns解析服务器地址
* 如果内网环境，搭建NTP服务器。其他节点统一同步NTP服务器的时间
# 部署前准备
必须安装ipvs
```
modprobe -- ip_vs
modprobe -- ip_vs_rr
modprobe -- ip_vs_wrr
modprobe -- ip_vs_sh
```

## [可选] 安装dns服务器
* 利用dnsmasq搭建测试域名解析服务器

## [可选] 搭建域名harbor服务器
步骤略
## [可选] 各部署节点配置dns服务器
注意事项：
1. 不要直接修改/etc/resolv.conf，确认由哪个程序修改，修改对应的配置。
2. 测试dns服务器的排序在配置第一位


# 想法
 根据master0和其他节点机制， 能够实现一个自动ha的机制。该机制用于在
* 新增Master节点，更改已存在Master节点/新master节点所在主机上haproxy后端服务器列表以及在新增的master节点上配置keepalived.
* 删除Master节点时，更改已存在Master节点点所在主机上haproxy后端服务器列表以及停止移除的master节点上的keepalived服务。
# 环境
* 三个节点： 10.30.12.203-205
* VIP: 10.30.12.249
* apiserver端口：6443
* VIP对外端口:8443

## 从代码实现的角度
1. 需要实现一个setupMaster的接口, 负责部署master0节点
    * 包括keepalived/haproxy服务和配置
2. 需要实现一个joinCluster，根据参数分为部署masterN节点和部署工作节点
    * 部署MasterN节点的话，同时还需要配置keepalived/haproxy服务及配置
         * 通过代码的方式去注入N台master地址到haproxy的配置比较麻烦，第一次可以通过template的方式来进行
         * 但要实现动态的就非常麻烦
         * https://github.com/haproxytech/dataplaneapi， 基于haproxy封装了restapi
    * keepalived中需要处理routerid(最好随机生成route id,以免同一网段出现同样的routeid )/各个master节点的priority/脚本执行失败时所减的权重·
    *
3. 需要实现一个接口用于获取部署MasterN或者部署工作节点的kubeadm join命令。

# 警告
1. 如果k8s组件/keepalived/haproxy/pause镜像都存放在私有镜像仓库的非公开项目中。kubelet无法从中拉取镜像时会报“require docker login日志”。
即使执行了docker login <registry>也不行，必须要将docker login后生成的config.json文件拷贝到/var/lib/kubelet中，这样kubelet才能通过私有镜像
仓库的验证从而拉取需要的镜像。
2. 如果kubelet不是通过apt等安装工具安装的，则必须要创建/etc/systemd/system/kubelet.service.d/10-kubeadm.conf
见kubeadm大坑
内容如下：
```
# Note: This dropin only works with kubeadm and kubelet v1.11+
[Service]
Environment="KUBELET_KUBECONFIG_ARGS=--bootstrap-kubeconfig=/etc/kubernetes/bootstrap-kubelet.conf --kubeconfig=/etc/kubernetes/kubelet.conf"
Environment="KUBELET_CONFIG_ARGS=--config=/var/lib/kubelet/config.yaml"
# This is a file that "kubeadm init" and "kubeadm join" generates at runtime, populating the KUBELET_KUBEADM_ARGS variable dynamically
EnvironmentFile=-/var/lib/kubelet/kubeadm-flags.env
# This is a file that the user can use for overrides of the kubelet args as a last resort. Preferably, the user should use
# the .NodeRegistration.KubeletExtraArgs object in the configuration files instead. KUBELET_EXTRA_ARGS should be sourced from this file.
EnvironmentFile=-/etc/default/kubelet
ExecStart=
ExecStart=/usr/bin/kubelet $KUBELET_KUBECONFIG_ARGS $KUBELET_CONFIG_ARGS $KUBELET_KUBEADM_ARGS $KUBELET_EXT
RA_ARGS
```
3. kubeadm init --upload-certs会在k8s集群创建一个kubeadm-crets命名的secret, 但这个secret存在TTL（默认2分钟），会自动消失
    * 需要执行`kubeadm init phase upload-certs --upload-certs` 该命令来重新生成，这条命令同样会返回cert key.
    * 最好指定kubeadm.yaml来指定kubernetes version.
    * 该secret的TTL是谁做的？（secret的机制，secret是有一个AGE）

#  kubeadm配置
### kubeadm.yaml
可以通过`kubeadm config print init-defaults --component-configs KubeProxyConfiguration,KubeletConfiguration`来获取默认的（如果KubeProxyConfiguration不需要更改，可以不传。）

主要目的：
* 可以更改kubelet的cgroup driver等配置
* 配置更加统一 
* 注意 通过上述命令，有些字段是动态生成的，比如说`nodeRegistration.name`, 如果没传,kubeadm默认使用主机名。可以直接把这个字段移掉或者置空。kubelet会默认填充当前节点名。这样可以避免节点名冲突的问题。
    * 注意，如果节点名不满足`[a-z0-9]([-a-z0-9]*[a-z0-9])?`,如（HCITos_cvm，这个名字就不满足）
    * 校验函数：
    ```
    const DNS1123LabelMaxLength int = 63
    const dns1123LabelFmt string = "[a-z0-9]([-a-z0-9]*[a-z0-9])?"
    const dns1123SubdomainFmt string = dns1123LabelFmt + "(\\." + dns1123LabelFmt + ")*"

    var dns1123LabelRegexp = regexp.MustCompile("^" + dns1123LabelFmt + "$")

    func isDNS1123Label(value string) error {
    	if len(value) > DNS1123LabelMaxLength {
    		return fmt.Errorf("name too long")
    	}
    	if !dns1123LabelRegexp.MatchString(value) {
    		return fmt.Errorf("not match name pattern: " + dns1123LabelRegexp.String())
    	}
    	return nil
    }
    ```
    * 后续获取kubeadm token create也会校验节点名，如果不使用主机名，kubeadm token create 应该指定--config kubeadm.yaml来使用配置文件中的名字。
    
kubeadm.yaml:
```
apiVersion: kubeadm.k8s.io/v1beta2
bootstrapTokens:
- groups:
  - system:bootstrappers:kubeadm:default-node-token
  # token: abcdef.0123456789abcdef， 不指定，由kubeadm token create来生成，避免已存在报错。
  ttl: 24h0m0s
  usages:
  - signing
  - authentication
kind: InitConfiguration
localAPIEndpoint:
  advertiseAddress: 10.30.12.203 # 改成当前节点
  bindPort: 6443        # 端口
nodeRegistration:
  criSocket: /var/run/dockershim.sock
  name: container-12-203     # kubelet节点名，不同节点填写不同的，不然会有节点注册失败
  taints:
  - effect: NoSchedule
    key: node-role.kubernetes.io/master
---
apiServer:
  timeoutForControlPlane: 4m0s
apiVersion: kubeadm.k8s.io/v1beta2
certificatesDir: /etc/kubernetes/pki
clusterName: kubernetes
controllerManager: {}
dns:
  type: CoreDNS
etcd:
  local:
    dataDir: /var/lib/etcd
imageRepository: 10.30.12.169/k8s.gcr.io # 指定镜像仓库
kind: ClusterConfiguration 
kubernetesVersion: v1.18.0
networking:
  dnsDomain: cluster.local
  serviceSubnet: 10.96.0.0/12
scheduler: {}
controlPlaneEndpoint: 10.30.12.249:6443 # VIP地址
---
apiVersion: kubelet.config.k8s.io/v1beta1
authentication:
  anonymous:
    enabled: false
  webhook:
    cacheTTL: 0s
    enabled: true
  x509:
    clientCAFile: /etc/kubernetes/pki/ca.crt
authorization:
  mode: Webhook
  webhook:
    cacheAuthorizedTTL: 0s
    cacheUnauthorizedTTL: 0s
clusterDNS:
- 10.96.0.10
clusterDomain: cluster.local
cpuManagerReconcilePeriod: 0s
evictionPressureTransitionPeriod: 0s
fileCheckFrequency: 0s
healthzBindAddress: 127.0.0.1
healthzPort: 10248
httpCheckFrequency: 0s
imageMinimumGCAge: 0s
kind: KubeletConfiguration
nodeStatusReportFrequency: 0s
nodeStatusUpdateFrequency: 0s
rotateCertificates: true
runtimeRequestTimeout: 0s
staticPodPath: /etc/kubernetes/manifests
streamingConnectionIdleTimeout: 0s
syncFrequency: 0s
volumeStatsAggPeriod: 0s
cgroupDriver: systemd # 指定 cgroup driver为systemd
---
apiVersion: kubeproxy.config.k8s.io/v1alpha1
bindAddress: 0.0.0.0
clientConnection:
  acceptContentTypes: ""
  burst: 0
  contentType: ""
  kubeconfig: /var/lib/kube-proxy/kubeconfig.conf
  qps: 0
clusterCIDR: ""
configSyncPeriod: 0s
conntrack:
  maxPerCore: null
  min: null
  tcpCloseWaitTimeout: null
  tcpEstablishedTimeout: null
detectLocalMode: ""
enableProfiling: false
healthzBindAddress: ""
hostnameOverride: ""
iptables:
  masqueradeAll: false
  masqueradeBit: null
  minSyncPeriod: 0s
  syncPeriod: 0s
ipvs:
  excludeCIDRs: null
  minSyncPeriod: 0s
  scheduler: ""
  strictARP: false
  syncPeriod: 0s
  tcpFinTimeout: 0s
  tcpTimeout: 0s
  udpTimeout: 0s
kind: KubeProxyConfiguration
metricsBindAddress: ""
mode: ""
nodePortAddresses: null
oomScoreAdj: null
portRange: ""
showHiddenMetricsForVersion: ""
udpIdleTimeout: 0s
winkernel:
  enableDSR: false
  networkName: ""
  sourceVip: ""

```
要改的点：
* nodeRegistration.name  注册节点名
* localAPIEndpoint.advertiseAddress: 当前节点地址
* localAPIEndpoint.bindPort：  apiserver监听的端口
* imageRepository: 10.30.12.169/k8s.gcr.io # 指定镜像仓库,如果在私有镜像库里没有项目，后面可以不接项目
* controlPlaneEndpoint: 10.30.12.249:8443# VIP地址
* cgroupDriver: systemd # 指定 cgroup driver为systemd，默认是cgroupfs



# 203节点
## keepalived
创建keepalived.yaml,放在/etc/kubernetes/manifests/下
```
apiVersion: v1
kind: Pod
metadata:
  creationTimestamp: null
  name: keepalived
  namespace: kube-system
spec:
  containers:
  - image: 10.30.12.169/k8s.gcr.io/keepalived:1.3.5-1
    name: keepalived
    resources: {}
    securityContext:
      capabilities:
        add:
        - NET_ADMIN
        - NET_BROADCAST
        - NET_RAW
    volumeMounts:
    - mountPath: /usr/local/etc/keepalived/keepalived.conf
      name: config
    - mountPath: /etc/keepalived/check_apiserver.sh
      name: check
  hostNetwork: true
  volumes:
  - hostPath:
      path: /etc/keepalived/keepalived.conf
    name: config
  - hostPath:
      path: /etc/keepalived/check_apiserver.sh
    name: check
status: {}
```

创建/etc/keepalived/keepalived.conf
```bash
! /etc/keepalived/keepalived.conf
! Configuration File for keepalived
global_defs {
    router_id LVS_DEVEL
}
vrrp_script check_apiserver {
  script "/etc/keepalived/check_apiserver.sh" # 注意确认脚本能不能执行; 
  interval 3 # 每次脚本执行间隔
  weight -5  # 失败后权重-5
  fall 10 # 失败多少次认为失败
  rise 5 # 成功多少次算成功
}

vrrp_instance VI_1 {
    state MASTER
    interface ens5
    virtual_router_id 51 # 这个值不能为0，如果当前子网，存在其他keepalived集群，virtual_router_id不能相同。
    priority 100 # 默认优先级
    authentication {
        auth_type PASS
        auth_pass 42
    }
    virtual_ipaddress {
        10.30.12.249
    }
    track_script {
        check_apiserver
    }
}

```
这里要改的点：
* vrrp_instance.State  : MASTER或者BACKUP, 这里设置为MASTER
* vrrp_instance.interface: ip a看下网卡名
* vrrp_instance.virtual_router_id: 直接写死51.不能和其他的一样。
* vrrp_instance.priority:  主节点填高，备份节点添低点。101/100
    * 注意这个优先级设置非常重要。必须要和weight计算后一起配置
    * keepalived脚本的逻辑时每隔internal(当前为3)执行check-apiserver脚本.当脚本执行失败超过10次, priority减去weight(当前为5)
        * 即当master一直check-apiserver脚本执行失败后，其权重(priority)将会从100减少至95.
        * 如果其他backup的priority高于当前Master的priority时, VIP将会漂移到最高优先级的Backup。如果没有，VIP仍然在这台Master节点上。
        * 如果存在同样权重的Backup时，VIP则不知道如何漂移时则仍然保留到当前节点上。
        * 因此当某个节点故障时，其priority-weight必须低于priority最低的节点, 这样才有可能VIP漂移到健康的priority较低的节点上。
        * 可以设计priority分别为(100,98,96)，weight设置为(5), 当master出现问题时， master prioriy减少至95，其他两台Backup就可以获取VIP漂移的可能。
* vrrp_instance.authentication.auth_pass: 写死42
* vrrp_instance.virtual_ipaddress: 填写虚IP

创建/etc/keepalived/check_apiserver.sh
```
#!/bin/sh

APISERVER_DEST_PORT=8443 # vip port
APISERVER_VIP=10.30.12.249
errorExit() {
    echo "*** $*" 1>&2
    exit 1
}

curl --silent --max-time 2 --insecure https://localhost:${APISERVER_DEST_PORT}/ -o /dev/null || errorExit "Error GET https://localhost:${APISERVER_DEST_PORT}/"
if ip addr | grep -q ${APISERVER_VIP}; then
    curl --silent --max-time 2 --insecure https://${APISERVER_VIP}:${APISERVER_DEST_PORT}/ -o /dev/null || errorExit "Error GET https://${APISERVER_VIP}:${APISERVER_DEST_PORT}/"
fi

```
### 补充一
上面的配置中keepalived为抢占模式: 当master挂掉后,VIP飘到backup1；当master恢复后, VIP会从backup1重新飘回到master
实际上我们可能并不需要一直在master上跑(除非说master节点性能非常好,备机性能一般)。则可以将keepalived设置为非抢占模式。

非抢占模式下，所有节点都设置为BACKUP，不能有节点设置为MASTER.
```
vrrp_instance VI_1
{
　　state BACKUP # 所有节点都要设置为BACKUP
　　nopreempt #  设置为非抢占模式
　　priority 100
```
## haproxy
创建haproxy.yaml,放到/etc/kubernetes/manifests
```
apiVersion: v1
kind: Pod
metadata:
  name: haproxy
  namespace: kube-system
spec:
  containers:
  - image: 10.30.12.169/k8s.gcr.io/haproxy:2.1.4
    name: haproxy
    livenessProbe:
      failureThreshold: 8
      httpGet:
        host: localhost
        path: /healthz
        port: 8443  # VIP端口
        scheme: HTTPS
    volumeMounts:
    - mountPath: /usr/local/etc/haproxy/haproxy.cfg
      name: haproxyconf
      readOnly: true
  hostNetwork: true
  volumes:
  - hostPath:
      path: /etc/haproxy/haproxy.cfg
      type: FileOrCreate
    name: haproxyconf
status: {}
```


创建/etc/haproxy/haproxy.cfg()
```
# 警告：以下配置从官网文档提供的配置虽然能够正常安装高可用集群。但是
# 查看部署好以后的kubeapiserver 容器日志时，会有大量的，机器频繁的报错信息,每隔两秒报一次。
# I0811 07:32:36.748706       1 log.go:172] http: TLS handshake error from 10.30.12.204:48118: tls: client offered 
# 使用haproxy.cfg kubeadm中的配置参考
only unsupported versions: [300]
# /etc/haproxy/haproxy.cfg
#---------------------------------------------------------------------
# Global settings
#---------------------------------------------------------------------
global
    log /dev/log local0
    log /dev/log local1 notice
    daemon

#---------------------------------------------------------------------
# common defaults that all the 'listen' and 'backend' sections will
# use if not designated in their block
#---------------------------------------------------------------------
defaults
    mode                    http
    log                     global
    option                  httplog
    option                  dontlognull
    option http-server-close
    option forwardfor       except 127.0.0.0/8
    option                  redispatch
    retries                 1
    timeout http-request    10s
    timeout queue           20s
    timeout connect         5s
    timeout client          20s
    timeout server          20s
    timeout http-keep-alive 10s
    timeout check           10s

#---------------------------------------------------------------------
# apiserver frontend which proxys to the masters
#---------------------------------------------------------------------
frontend apiserver
    bind *:${APISERVER_DEST_PORT}
    mode tcp
    option tcplog
    default_backend apiserver

#---------------------------------------------------------------------
# round robin balancing for apiserver
#---------------------------------------------------------------------
backend apiserver
    option httpchk GET /healthz
    http-check expect status 200
    mode tcp
    option ssl-hello-chk
    balance     roundrobin
        server ${HOST1_ID} ${HOST1_ADDRESS}:${APISERVER_SRC_PORT} check
        # [...]
```
需要改的点：
* ${APISERVER_DEST_PORT}： VIP端口 8443
* ${HOST1_ID}:  这里填主机名
* ${HOST1_ADDRESS}： 当前节点ip 10.30.12.203
* ${APISERVER_SRC_PORT}： 6443

### 补充1： haproxy.cfg kubeadm中的配置
这里和官网的区别在于，移除了ssl-hello-chk(使用的SSLV3)，添加了check时verify. 
* 参考https://github.com/kubernetes/kubernetes/issues/70411
```
# /etc/haproxy/haproxy.cfg
#---------------------------------------------------------------------
# Global settings
#---------------------------------------------------------------------
global
    log /dev/log local0
    log /dev/log local1 notice
    daemon

#---------------------------------------------------------------------
# common defaults that all the 'listen' and 'backend' sections will
# use if not designated in their block
#---------------------------------------------------------------------
defaults
    mode                    http
    log                     global
    option                  httplog
    option                  dontlognull
    option http-server-close
    option forwardfor       except 127.0.0.0/8
    option                  redispatch
    retries                 1
    timeout http-request    10s
    timeout queue           20s
    timeout connect         5s
    timeout client          20s
    timeout server          20s
    timeout http-keep-alive 10s
    timeout check           10s

#---------------------------------------------------------------------
# apiserver frontend which proxys to the masters
#---------------------------------------------------------------------
frontend apiserver
    bind *:8443
    mode tcp
    option tcplog
    default_backend apiserver
#---------------------------------------------------------------------
# round robin balancing for apiserver
#---------------------------------------------------------------------
backend apiserver
    option httpchk GET /healthz
    http-check expect status 200
    mode tcp
  #  option ssl-hello-chk
    balance     roundrobin
        server 10.30.12.203 10.30.12.203:6443 check check-ssl verify none
        server 10.30.12.204 10.30.12.204:6443 check check-ssl verify none
        server 10.30.12.205 10.30.12.205:6443 check check-ssl verify none

```
### 补充2： 需要调整haproxy的超时
在使用上面的haproxy配置部署高可用集群时，在实际使用中发现`kubectl exec -it <podName> bash`放置不动过了20秒后会连接会准时退出。查看了kubelet的代码，这是因为已经找不到对应的容器。kubelet有个参数可以配置空闲连接`--streaming-connection-idle-timeout`, 但默认设置为0(无超时)。
 通过这个 Issue `https://github.com/kubernetes/kubernetes/issues/66661`，可以确认是haproxy的超时配置导致(正好设置timeout client/server为20秒)
```yaml
# /etc/haproxy/haproxy.cfg
#---------------------------------------------------------------------
# Global settings
#---------------------------------------------------------------------
global
    log /dev/log local0
    log /dev/log local1 notice
    daemon

#---------------------------------------------------------------------
# common defaults that all the 'listen' and 'backend' sections will
# use if not designated in their block
#---------------------------------------------------------------------
defaults
    mode                    http
    log                     global
    option                  httplog
    option                  dontlognull
    option http-server-close
    option forwardfor       except 127.0.0.0/8
    option                  redispatch
    retries                 1
    timeout http-request    240s  
    timeout queue           240s 
    timeout connect         240s
    timeout client          4h  # 调整超时为4个小时
    timeout server          4h  # 调整超时为4个小时
    timeout http-keep-alive 240s
    timeout check           240s

#---------------------------------------------------------------------
# apiserver frontend which proxys to the masters
#---------------------------------------------------------------------
frontend apiserver
    bind *:8443
    mode tcp
    option tcplog
    default_backend apiserver
#---------------------------------------------------------------------
# round robin balancing for apiserver
#---------------------------------------------------------------------
backend apiserver
    option httpchk GET /healthz
    http-check expect status 200
    mode tcp
#    option ssl-hello-chk
    balance     roundrobin
                server 10.30.100.105 10.30.100.105:6443 check check-ssl verify none
        server 10.30.100.141 10.30.100.141:6443 check check-ssl verify none
        server 10.30.100.189 10.30.100.189:6443 check check-ssl verify none

```
### 补充3 haproxy的配置说明
参考1： https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/load_balancer_administration/s1-haproxy-setup-defaults

参考2： https://blog.csdn.net/bbwangj/article/details/80337994

* `retries` specifies the number of times a real server will retry a connection request after failing to connect on the first try.
*  The various `timeout` values specify the length of time of inactivity for a given request, connection, or response. These values are generally expressed in milliseconds (unless explicitly stated otherwise) but may be expressed in any other unit by suffixing the unit to the numeric value. Supported units are us (microseconds), ms (milliseconds), s (seconds), m (minutes), h (hours) and d (days).
    * `http-request 10s` gives 10 seconds to wait for a complete HTTP request from a client.
    * `queue 1m` sets one minute as the amount of time to wait before a connection is dropped and a client receives a 503 or "Service Unavailable" error. 
    * `connect 10s` specifies the number of seconds to wait for a successful connection to a server. 
    * `client 1m`specifies the amount of time (in minutes) a client can remain inactive (it neither accepts nor sends data).
    * `server 1m` specifies the amount of time (in minutes) a server is given to accept or send data before timeout occurs.

## 创建control-plane
```
kubeadm init --config ./kubeadm.yaml  --upload-certs
```
这里成功执行后，会有两种join命令打印出来(和单点的不同)
* 控制面板添加 `kubeadm join 10.30.12.249:8443 --token abcdef.0123456789abcdef --discovery-token-ca-cert-hash sha256:b819a19c32fbd5277c98ba298cf1d0948ede1dcf4cb371d84be465daaa9d8c4e --control-plane --certificate-key 4d85898f8d1c020f18eeddf709af88a49089ab7caf7241323a61aa88564ec147`
* 工作节点添加 `kubeadm join 10.30.12.249:8443 --token abcdef.0123456789abcdef --discovery-token-ca-cert-hash sha256:b819a19c32fbd5277c98ba298cf1d0948ede1dcf4cb371d84be465daaa9d8c4e`
* 这里的作用是：
    * 将当前节点生成的ca.kye/ca.crt/etcd.key/etcd.crt/等证书进行AES加密后保存到kube-system中的kubeadm-certs secret中
    * 上面join命令``` 4d85898f8d1c020f18eeddf709af88a49089ab7caf7241323a61aa88564ec147`是用来对secret中的数据进行解密
    * 源码参考k8s.io\kubernetes\cmd\kubeadm\app\phases\copycerts\copycerts.go的DownloadCerts函数(1.18.0)
## `--certificate-key`
certificate-key获取的方式有两种：
* `kubeadm alpha certs certificate-key --logtostderr=false` 
    * 仅限于kubeadm-certs secret（kubeadm-certs secret有TTL时间）
* `kubeadm init phase upload-certs  --upload-certs --config kubeadm.yaml --logtostderr=false`
    * 会创建一个新的kubeadm-certs
    * --config指定kubeadm的配置文件，目的是指定集群版本

## 204/205节点
* keepalived.yaml 移到/etc/kubernetes/manifests下
* keepalived.conf check_apiserver.sh， 注意更改优先级/MASTER BACKUP状态以及VIP端口后移动到 /etc/keepalived/
* haproxy.yaml 移到/etc/kubernetes/manifests下
* haproxy.cfg , 同203修改移到/etc/haproxy
* 执行join control plane命令，并加上忽略/etc/kubernetes/manifests不为空错误
    * `kubeadm join 10.30.12.249:8443 --token abcdef.0123456789abcdef     --discovery-token-ca-cert-hash sha256:4e30a106f4d5349ee83576fb0d8142cf05a83d6e2e61cc9fb4ba5f8fafc74365     --control-plane --certificate-key 489a4ba06a6598948ee5a381ffc955bf81c7e943ef5f0faa805b2e9dca5a95b5 --ignore-preflight-errors=DirAvailable--etc-kubernetes-manifests`
    * 这样join以后能够保证keepalived/haproxy能够正常启动

# 可选
etcd配置更长的选举/心跳超时时长？
```
kind: Pod
metadata:
  annotations:
    kubeadm.kubernetes.io/etcd.advertise-client-urls: https://10.30.12.203:2379
  creationTimestamp: null
  labels:
    component: etcd
    tier: control-plane
  name: etcd
  namespace: kube-system
spec:
  containers:
  - command:
    - etcd
    - --advertise-client-urls=https://10.30.12.203:2379
    - --cert-file=/etc/kubernetes/pki/etcd/server.crt
    - --client-cert-auth=true
    - --data-dir=/var/lib/etcd
    - --initial-advertise-peer-urls=https://10.30.12.203:2380
    - --initial-cluster=container-12-203=https://10.30.12.203:2380
    - --key-file=/etc/kubernetes/pki/etcd/server.key
    - --listen-client-urls=https://127.0.0.1:2379,https://10.30.12.203:2379
    - --listen-metrics-urls=http://127.0.0.1:2381
    - --listen-peer-urls=https://10.30.12.203:2380
    - --name=container-12-203
    - --peer-cert-file=/etc/kubernetes/pki/etcd/peer.crt
    - --peer-client-cert-auth=true
    - --peer-key-file=/etc/kubernetes/pki/etcd/peer.key
    - --peer-trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt
    - --snapshot-count=10000
    - --trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt
    - --heartbeat-interval=1000 # 默认100ms
    - --election-timeout=5000 # 默认100ms
```

# 验证
1. 当前是否三个节点
2. 查看是否有三个etcd/keepalived/haproxy pod存在
3. etcd集群是否正常, 见下面
4. ip a看哪个节点当前挂着VIP，将其中/etc/kubernetes/manifests/keepalived.yaml移动到其他地方（static pod会被删除）。再看下VIP会不会迁移到其他节点，kubectl是否能够正常使用。

### apiserver 是否正常
`curl https://127.0.0.1:6443/healthz --insecure`
### etcd集群是否正常
1. 通过docker cp从etcd容器里拷贝etcdctl出来docker cp  1792c8051de8:/usr/local/bin/etcdctl /usr/local/bin/
2. ` etcdctl --endpoints=10.30.12.203:2379  --command-timeout=60s --cacert=/etc/kubernetes/pki/etcd/ca.crt --cert=/etc/kubernetes/pki/apiserver-etcd-client.crt --key=/etc/kubernetes/pki/apiserver-etcd-client.key  member list` 执行成功即可
    * 注意一定要加上tls证书，否则会报:
    ```
    {"level":"warn","ts":"2020-07-31T15:00:47.289+0800","caller":"clientv3/retry_interceptor.go:61","msg":"retrying of unary invoker failed","target":"endpoint://client-8595cd7b-2275-460e-a1ad-6cd20e9eb8c7/10.30.12.203:2379","attempt"
    :0,"error":"rpc error: code = DeadlineExceeded desc = latest connection error: connection closed"}Error: context deadline exceeded
    ```
3. 获取etcd的leader
    `etcdctl --endpoints=10.30.100.67:2379,https://10.30.100.147:2379,https://10.30.100.85:2379 --command-timeout=60s --cacert=/etc/kubernetes/pki/etcd/ca.crt --cert=/etc/kubernetes/pki/apiserver-etcd-client.crt --key=/etc/kubernetes/pki/apiserver-etcd-client.key -w table endpoint status
`
### haproxy是否正常工作
1. 查看已启用的haproxy pod,查看其中的日志
2. 如果正常应该可以看到其他节点UP和有多少个active服务器的信息
```
[WARNING] 222/124543 (6) : Server apiserver/10.30.12.204 is UP, reason: Layer6 check passed, check duration: 1ms.
 2 active and 0 backup servers online. 0 sessions requeued, 0 total in queue.[WARNING] 222/124835 (6) : Server apiserver/10.30.12.205 is UP, reason: Layer6 check passed, check duration: 0ms.
 3 active and 0 backup servers online. 0 sessions requeued, 0 total in queue.
```

### keepalived是否能正常切换VIP
需要测试

# 安装网络插件
1. https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/create-cluster-kubeadm/#pod-network
2. 网络插件 https://kubernetes.io/docs/concepts/cluster-administration/networking/#how-to-implement-the-kubernetes-networking-model


# 清理（反向操作）
1. kubeadm reset -f清理k8s集群
2. rm /etc/keepalived/keepalived.conf
3. rm /etc/keepalived/check_apiserver.sh
4. rm /etc/haproxy/haproxy.cfg
5. ip add del 10.30.12.249/32 dev ens5 //移除网卡上的虚IP

```

#!/bin/bash
VIP=10.30.12.239
INTF=ens5
kubeadm reset -f
docker rmi -f `docker images | grep k8s.gcr | awk '{print $3}'`
rm /usr/bin/kubelet-pre-start.sh  >/dev/null 2>&1 || true
rm /lib/systemd/system/kubelet.service >/dev/null 2>&1  ||  true
rm /root/.docker/config.json  >/dev/null 2>&1 || true
rm /etc/keepalived/keepalived.conf || true
rm /etc/keepalived/check_apiserver.sh || true
rm /etc/haproxy/haproxy.cfg || true
if ip addr | grep -q $VIP; then
   ip addr del $VIP/32 dev $INTF
fi
```
# 其余遇到的问题
1. 在一个部署的ha集群的k8s节点上，执行kubeadm清理以后重新部署成ha master.集群已经能正常访问了，但发现keepalived Pod根本没有正常运行
    * 原因：上次ha集群生成VIP没有删除，清理ha集群时必须手动清理虚IP  ip add del 10.30.12.249/32 dev ens5 
    * 清理VIP，k8s环境后重新部署即可。
2. 部署过程中keepalived无法正常被kubelet带起来，无法生成VIP.
    * https://github.com/acassen/keepalived/issues/820 这个issue遇到同样的问题。
# 参考
* https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/high-availability/
* https://github.com/kubernetes/kubeadm/blob/master/docs/ha-considerations.md#options-for-software-load-balancing
* https://www.kubernetes.org.cn/6964.html
* 转换成ha集群 https://blog.scottlowe.org/2019/08/12/converting-kubernetes-to-ha-control-plane/
