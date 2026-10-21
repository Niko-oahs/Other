# 1. 备份现有源文件
sudo cp /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo.backup

# 2. 写入 Kernel.org 归档源
sudo bash -c 'cat << EOF > /etc/yum.repos.d/CentOS-Base.repo
[base]
name=CentOS-7.9.2009 - Base - Kernel.org
baseurl=http://archive.kernel.org/centos-vault/7.9.2009/os/\$basearch/
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7
enabled=1

[updates]
name=CentOS-7.9.2009 - Updates - Kernel.org
baseurl=http://archive.kernel.org/centos-vault/7.9.2009/updates/\$basearch/
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7
enabled=1

[extras]
name=CentOS-7.9.2009 - Extras - Kernel.org
baseurl=http://archive.kernel.org/centos-vault/7.9.2009/extras/\$basearch/
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7
enabled=1
EOF'

# 3. 清理并快速构建缓存
sudo yum clean all
sudo yum makecache fast

# 4. 重新执行系统更新
sudo yum update -y
