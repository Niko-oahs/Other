# cenos更换源
sudo cp /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo.backup

sudo bash -c 'cat << EOF > /etc/yum.repos.d/CentOS-Base.repo
[centos]
name=CentOS-\$releasever - Base - Aliyun
baseurl=http://mirrors.aliyun.com/centos/\$releasever/os/\$basearch/
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7
enabled=1

[centos-fasttrack]
name=CentOS - Fasttrack
mirrorlist=http://mirrors.aliyun.com/centos/7/fasttrack
baseurl=http://mirrors.aliyun.com/centos/7/fasttrack
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7
enabled=0

[extras]
name=CentOS-\$releasever - Extras
baseurl=http://mirrors.aliyun.com/centos/\$releasever/extras/\$basearch/
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7
enabled=1

[updates]
name=CentOS-\$releasever - Updates
baseurl=http://mirrors.aliyun.com/centos/\$releasever/updates/\$basearch/
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7
enabled=1
EOF'
sudo yum clean all
sudo yum makecache

# 必要更新
sudo yum update -y
sudo yum install -y yum-utils
# 安装防火墙：
sudo yum install firewalld
# 打开防火墙
sudo systemctl start firewalld
# 设置防火墙开机启动
sudo systemctl enable firewalld
