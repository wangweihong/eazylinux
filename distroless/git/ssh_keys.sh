#!/usr/bin/env bash

MyEmail="test@example.com"
MyName="test"

# 1. unset global user name and email
git config --global --unset user.name
git config --global --unset user.email


# 2. generate ssh keys
## for better managerment, ssh-keygen generated key saved in eazy-understand name
##root@wwhvw:~/.ssh# ssh-keygen -t rsa -C "test@example.com"
##Generating public/private rsa key pair.
##Enter file in which to save the key (/root/.ssh/id_rsa): id_rsa_github
cd ~/.ssh
ssh-keygen -t rsa -C "$MyEmail"


# 3. copy id_rsa_github.pub file and paste to github/<Your Profile>/Setting/SSH and GPG keys

# 4. make sure ssh-agent run
eval `ssh-agent -s`

# 5. add ssh-key
ssh-add ~/.ssh/id_rsa_github

# 6. write ssh config
cat <<EOF >> ~/.ssh/config

Host github
HostName github.com
User $MyName
IdentityFile ~/.ssh/id_rsa_github
EOF

## if multiple keys
#cat <<EOF >> ~/.ssh/config
#Host github
#HostName github.com
#User test
#IdentityFile ~/.ssh/id_rsa_github
#
#
#Host gitlab
#HostName gitlab.com
#User test 
#IdentityFile ~/.ssh/id_rsa_gitlab
#EOF

# 7. test if ssh key ok
ssh -vT git@github.com
