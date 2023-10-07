#!/usr/bin/env bash
set -e
set -x
docker pull registry.cn-hangzhou.aliyuncs.com/anoy/yapi
docker run -d --name mongo-yapi -p 27017:27017 -v /root/yapi:/data/db mongo
docker run -it --rm --link mongo-yapi:mongo --entrypoint npm --workdir /api/vendors registry.cn-hangzhou.aliyuncs.com/anoy/yapi run install-server
docker run -d --name yapi --link mongo-yapi:mongo --workdir /api/vendors -p 10001:3000/tcp registry.cn-hangzhou.aliyuncs.com/anoy/yapi server/app.js
