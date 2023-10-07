#!/usr/bin/env bash
# scripts to install system dig tools
set -e

# disk usage statistic
apt install -y ncdu
# cpu/mem statistic, better than top
apt install -y htop

