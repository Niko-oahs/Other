# CentOS 更换为腾讯云源
sudo cp /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo.backup

sudo bash -c 'cat << EOF > /etc/yum.repos.d/CentOS-Base.repo
[base]
name=CentOS-7.9.2009 - Base - Tencent
baseurl=https://mirrors.cloud.tencent.com/centos-vault/7.9.2009/os/\$basearch/
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7
enabled=1

[updates]
name=CentOS-7.9.2009 - Updates - Tencent
baseurl=https://mirrors.cloud.tencent.com/centos-vault/7.9.2009/updates/\$basearch/
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7
enabled=1

[extras]
name=CentOS-7.9.2009 - Extras - Tencent
baseurl=https://mirrors.cloud.tencent.com/centos-vault/7.9.2009/extras/\$basearch/
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7
enabled=1

[centosplus]
name=CentOS-7.9.2009 - Plus - Tencent
baseurl=https://mirrors.cloud.tencent.com/centos-vault/7.9.2009/centosplus/\$basearch/
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7
enabled=0
EOF'

# 清理并重建缓存
sudo yum clean all
sudo yum makecache

# 必要更新
sudo yum update -y
sudo yum install -y yum-utils

# 安装防火墙并启动（补充了 -y 参数避免脚本执行被中断）
sudo yum install -y firewalld
sudo systemctl start firewalld
sudo systemctl enable firewalld
