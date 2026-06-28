#!/bin/bash
# ============================================
# 清除旧版 SSH 防护系统配置
# 适用: iptables + ipset 版本
# ============================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

echo ""
echo -e "${RED}=========================================${NC}"
echo -e "${RED}  清除 SSH 防护系统旧配置${NC}"
echo -e "${RED}=========================================${NC}"
echo ""

# ============================================
# 1. 停止并禁用旧服务
# ============================================
print_info "停止旧服务..."
systemctl stop ssh-ban.service 2>/dev/null
systemctl disable ssh-ban.service 2>/dev/null
rm -f /etc/systemd/system/ssh-ban.service
systemctl daemon-reload

# ============================================
# 2. 删除旧脚本
# ============================================
print_info "删除旧脚本..."
rm -f /usr/local/bin/ban_failed_ssh.sh
rm -f /usr/local/bin/ban-manager

# ============================================
# 3. 清除 iptables 规则
# ============================================
print_info "清除 iptables 规则..."

# 删除 SSH_BAN 链
iptables -F SSH_BAN 2>/dev/null
iptables -X SSH_BAN 2>/dev/null
ip6tables -F SSH_BAN_V6 2>/dev/null
ip6tables -X SSH_BAN_V6 2>/dev/null

# 删除引用 SSH_BAN 的 INPUT 规则
iptables -L INPUT --line-numbers -n | grep SSH_BAN | awk '{print $1}' | tac | while read num; do
    iptables -D INPUT $num 2>/dev/null
done

ip6tables -L INPUT --line-numbers -n | grep SSH_BAN_V6 | awk '{print $1}' | tac | while read num; do
    ip6tables -D INPUT $num 2>/dev/null
done

# ============================================
# 4. 删除 ipset
# ============================================
print_info "删除 ipset..."
ipset flush ssh_ban_set 2>/dev/null
ipset destroy ssh_ban_set 2>/dev/null

# ============================================
# 5. 清除 firewalld 中的残留（如果有）
# ============================================
print_info "清除 firewalld 中的残留..."
firewall-cmd --permanent --remove-rich-rule='rule family="ipv4" source ipset="ssh_ban_set" drop' 2>/dev/null
firewall-cmd --permanent --delete-ipset=ssh_ban_set 2>/dev/null
firewall-cmd --reload 2>/dev/null

# 删除可能残留的 direct 规则
firewall-cmd --permanent --direct --remove-rule ipv4 filter INPUT 0 -m set --match-set ssh_ban_set src -j DROP 2>/dev/null
firewall-cmd --permanent --direct --remove-rule ipv6 filter INPUT 0 -m set --match-set ssh_ban_set src -j DROP 2>/dev/null

# ============================================
# 6. 删除配置文件
# ============================================
print_info "删除配置文件..."
rm -f /etc/ssh_ban_ports.conf
rm -f /etc/ssh_ban_whitelist.conf
rm -f /etc/banned_ips.txt
rm -f /etc/ipset.conf
rm -f /etc/profile.d/ssh-ban.sh

# ============================================
# 7. 删除日志
# ============================================
print_info "删除日志文件..."
rm -f /var/log/ssh_ban.log
rm -f /var/log/ssh_ban.log.*
rm -f /etc/logrotate.d/ssh-ban

# ============================================
# 8. 保存防火墙规则
# ============================================
print_info "保存防火墙规则..."

if command -v iptables-save &>/dev/null; then
    if [ -f /etc/redhat-release ]; then
        service iptables save 2>/dev/null
        service ip6tables save 2>/dev/null
    else
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
    fi
fi

print_info "清除完成！"

echo ""
echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}  ✅ 旧配置已完全清除${NC}"
echo -e "${GREEN}=========================================${NC}"
echo ""

# ============================================
# 9. 验证结果
# ============================================
echo -e "${YELLOW}验证结果:${NC}"
echo ""
echo -e "  📌 iptables SSH_BAN 链: $(iptables -L SSH_BAN 2>/dev/null | head -1 || echo '不存在 ✅')"
echo -e "  📌 ipset ssh_ban_set: $(ipset list ssh_ban_set 2>/dev/null | head -1 || echo '不存在 ✅')"
echo -e "  📌 服务: $(systemctl status ssh-ban.service 2>/dev/null | grep Active || echo '已停止 ✅')"
echo -e "  📌 脚本: $(ls -la /usr/local/bin/ban* 2>/dev/null || echo '已删除 ✅')"
echo ""
