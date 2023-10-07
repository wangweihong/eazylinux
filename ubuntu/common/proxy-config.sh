#!/usr/bin/env bash
# script for config apt/wget/curl/docker proxy
set -e

### NOTE
### replace by true proxy address
httpProxy=http://127.0.0.1:10811
httpsProxy=http://127.0.0.1:10811


# config apt proxy
aptConfigFile="/etc/apt/apt.conf"

# 检查是否存在 /etc/apt/apt.conf 文件
if [ ! -e "$aptConfigFile" ]; then
    echo "Creating $aptConfigFile and setting proxy..."
    cat <<EOF > "$aptConfigFile"
Acquire::http::Proxy "$httpProxy";
Acquire::https::Proxy "$httpsProxy";
EOF
else
    # 读取现有的代理设置
    currentHttpProxy=$(grep -oP 'Acquire::http::Proxy\s*"\K[^"]*' "$aptConfigFile")
    currentHttpsProxy=$(grep -oP 'Acquire::https::Proxy\s*"\K[^"]*' "$aptConfigFile")

    # 检查是否需要更新代理设置
    if [ "$currentHttpProxy" != "$httpProxy" ] || [ "$currentHttpsProxy" != "$httpsProxy" ]; then
        echo "Updating $aptConfigFile..."
        cat <<EOF > "$aptConfigFile"
Acquire::http::Proxy "$httpProxy";
Acquire::https::Proxy "$httpsProxy";
EOF
    else
        echo "$aptConfigFile already exists and is up to date."
    fi
fi


wgetrcFile="/etc/wgetrc"

# 检查是否存在 /etc/wgetrc 文件
if [ ! -e "$wgetrcFile" ]; then
    echo "Creating $wgetrcFile and setting proxy..."
    cat <<EOF > "$wgetrcFile"
use_proxy=yes
http_proxy=$httpProxy
https_proxy=$httpsProxy
EOF
else
    # 如果是默认配置文件，则直接替换
    sed -i -e "s!#https_proxy = http://proxy.yoyodyne.com:18023/!https_proxy = $httpsProxy!" "$wgetrcFile"
    sed -i -e "s!#http_proxy = http://proxy.yoyodyne.com:18023/!http_proxy = $httpProxy!" "$wgetrcFile"
    sed -i -e "s!#use_proxy = on!use_proxy = on!" "$wgetrcFile"
    # 读取现有的代理设置
    currentHttpProxy=$(grep -oP 'http_proxy\s*=\s*\K[^"]*' "$wgetrcFile")
    currentHttpsProxy=$(grep -oP 'https_proxy\s*=\s*\K[^"]*' "$wgetrcFile")


    # 检查是否需要更新代理设置
    if [ "$currentHttpProxy" != "$httpProxy" ] || [ "$currentHttpsProxy" != "$httpsProxy" ]; then
        echo "Updating $wgetrcFile..."
         # 替换现有的代理设置
        sed -i -e "s!http_proxy=.*!http_proxy=$httpProxy!" "$wgetrcFile"
        sed -i -e "s!https_proxy=.*!https_proxy=$httpsProxy!" "$wgetrcFile"
    else
        echo "$wgetrcFile already exists and is up to date."
    fi
fi



# config curl proxy
bashrcFile="$HOME/.bashrc"

# 检查是否存在 ~/.bashrc 文件
if [ ! -e "$bashrcFile" ]; then
    echo "Creating $bashrcFile and setting proxy..."
    cat <<EOF >> "$bashrcFile"
export http_proxy=$httpProxy
export https_proxy=$httpsProxy
EOF
else
    # 检查是否已经存在相应的代理设置
    if ! grep -q "export http_proxy=$httpProxy" "$bashrcFile" || ! grep -q "export https_proxy=$httpsProxy" "$bashrcFile"; then
        echo "Updating $bashrcFile..."
        echo "export http_proxy=$httpProxy" >> "$bashrcFile"
        echo "export https_proxy=$httpsProxy" >> "$bashrcFile"
    else
        echo "$bashrcFile already contains proxy settings."
    fi
fi

# 重新加载 bash 配置
source "$bashrcFile"

# config docker proxy
dockerProxyFile="/etc/systemd/system/docker.service.d/http-proxy.conf"

# 创建目录 /etc/systemd/system/docker.service.d/ 如果不存在
mkdir -p $(dirname "$dockerProxyFile")

# 检查是否存在代理配置文件 /etc/systemd/system/docker.service.d/http-proxy.conf
if [ ! -e "$dockerProxyFile" ]; then
    echo "Creating $dockerProxyFile and setting Docker proxy..."
    cat <<EOF > "$dockerProxyFile"
[Service]
Environment="HTTP_PROXY=$httpProxy"
Environment="HTTPS_PROXY=$httpsProxy"
EOF
else
    # 读取现有的代理设置
    currentHttpProxy=$(grep -oP 'Environment="HTTP_PROXY=\K[^"]*' "$dockerProxyFile")
    currentHttpsProxy=$(grep -oP 'Environment="HTTPS_PROXY=\K[^"]*' "$dockerProxyFile")

    # 检查是否需要更新代理设置
    if [ "$currentHttpProxy" != "$httpProxy" ] || [ "$currentHttpsProxy" != "$httpsProxy" ]; then
        echo "Updating $dockerProxyFile..."
        # 使用不同的分隔符来替换现有的代理设置
        sed -i "s|Environment=\"HTTP_PROXY=.*|Environment=\"HTTP_PROXY=$httpProxy\"|" "$dockerProxyFile"
        sed -i "s|Environment=\"HTTPS_PROXY=.*|Environment=\"HTTPS_PROXY=$httpsProxy\"|" "$dockerProxyFile"
    else
        echo "$dockerProxyFile already exists and is up to date."
    fi
fi

# 重新加载 Docker 服务配置
systemctl daemon-reload
# 重新启动 Docker 服务
systemctl restart docker