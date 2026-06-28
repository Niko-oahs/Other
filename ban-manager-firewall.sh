#!/bin/bash
# ============================================
# SSH 防护系统 v4.0 - firewalld 原生版
# 功能: 使用 firewalld ipset + rich rule
# ============================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# 检查 root
if [ "$EUID" -ne 0 ]; then
    print_error "请使用 root 权限运行"
    exit 1
fi

# 检测系统
if ! command -v firewall-cmd &>/dev/null; then
    print_error "firewalld 未安装，请先安装: yum install firewalld -y"
    exit 1
fi

print_header() {
    echo ""
    echo -e "${GREEN}=========================================${NC}"
    echo -e "${GREEN}$1${NC}"
    echo -e "${GREEN}=========================================${NC}"
}

# 检测 SSH 端口
SSH_PORT=$(grep "^Port" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
[ -z "$SSH_PORT" ] && SSH_PORT=22

print_header "配置 firewalld 黑名单"

# ============================================
# 1. 创建 ipset（黑名单集合）
# ============================================
print_info "创建 ipset: ssh_ban_set"
firewall-cmd --permanent --new-ipset=ssh_ban_set --type=hash:ip 2>/dev/null || {
    print_warning "ipset 已存在，跳过创建"
}

# ============================================
# 2. 创建 rich rule（封禁规则）
# ============================================
print_info "创建封禁规则（永久生效）"
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source ipset="ssh_ban_set" drop' 2>/dev/null || {
    print_warning "规则已存在，跳过添加"
}

# ============================================
# 3. 重载防火墙
# ============================================
firewall-cmd --reload
print_success "防火墙配置完成"

# ============================================
# 4. 创建监控脚本
# ============================================
print_header "创建监控脚本"

cat > /usr/local/bin/ban_failed_ssh.sh << 'MONITOR_SCRIPT'
#!/bin/bash

# ============================================
# SSH 防护 v4.0 - firewalld 版监控脚本
# ============================================

# 日志文件
if [ -f /var/log/secure ]; then
    LOG_FILE="/var/log/secure"
elif [ -f /var/log/auth.log ]; then
    LOG_FILE="/var/log/auth.log"
else
    echo "错误：找不到 SSH 日志" >> /var/log/ssh_ban.log
    exit 1
fi

# 配置
IPSET_NAME="ssh_ban_set"
WHITELIST_FILE="/etc/ssh_ban_whitelist.conf"
MAX_RETRY=5
FIND_TIME=86400  # 24小时

# 检测 SSH 端口
SSH_PORT=$(grep "^Port" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
[ -z "$SSH_PORT" ] && SSH_PORT=22

# 确保白名单文件存在
[ -f "$WHITELIST_FILE" ] || touch "$WHITELIST_FILE"

# 检查是否在白名单
is_whitelisted() {
    local ip=$1
    grep -qx "$ip" "$WHITELIST_FILE" 2>/dev/null
}

# 关联数组记录失败次数
declare -A FAIL_COUNT
declare -A FIRST_FAIL_TIME

echo "$(date): SSH 防护 v4.0 (firewalld) 已启动，监控端口: $SSH_PORT" >> /var/log/ssh_ban.log

# 监控日志
tail -Fn0 "$LOG_FILE" | while read line; do
    if echo "$line" | grep -q "Failed password"; then
        # 提取 IP
        IP=$(echo "$line" | grep -oP 'from \K[0-9.]+' || echo "$line" | grep -oP 'from (::[0-9a-f:]+)' | awk '{print $2}')
        [ -z "$IP" ] && continue

        # 提取端口
        PORT=$(echo "$line" | grep -oP 'port \K[0-9]+' | head -1)

        # 检查白名单
        if is_whitelisted "$IP"; then
            continue
        fi

        # 检查是否已封禁
        if firewall-cmd --ipset="$IPSET_NAME" --query-entry="$IP" 2>/dev/null; then
            continue
        fi

        CURRENT_TIME=$(date +%s)

        # 记录失败次数
        if [ -z "${FIRST_FAIL_TIME[$IP]}" ]; then
            FIRST_FAIL_TIME[$IP]=$CURRENT_TIME
            FAIL_COUNT[$IP]=1
        else
            TIME_DIFF=$((CURRENT_TIME - FIRST_FAIL_TIME[$IP]))
            if [ $TIME_DIFF -le $FIND_TIME ]; then
                FAIL_COUNT[$IP]=$((FAIL_COUNT[$IP] + 1))
            else
                FIRST_FAIL_TIME[$IP]=$CURRENT_TIME
                FAIL_COUNT[$IP]=1
            fi
        fi

        # 达到封禁阈值
        if [ ${FAIL_COUNT[$IP]} -ge $MAX_RETRY ]; then
            # 使用 firewalld 封禁
            firewall-cmd --permanent --ipset="$IPSET_NAME" --add-entry="$IP" 2>/dev/null
            firewall-cmd --reload 2>/dev/null

            echo "$(date): 🔒 封禁 $IP (端口: $PORT, 失败 ${FAIL_COUNT[$IP]} 次)" | tee -a /var/log/ssh_ban.log

            # 记录到持久化文件
            echo "$IP" >> /etc/banned_ips.txt 2>/dev/null

            # 发送告警（如果配置了）
            if [ -n "$ALERT_EMAIL" ] && command -v mail &>/dev/null; then
                echo -e "IP: $IP\n端口: $PORT\n时间: $(date)" | mail -s "[SSH防护] 封禁 $IP" "$ALERT_EMAIL"
            fi

            unset FAIL_COUNT[$IP]
            unset FIRST_FAIL_TIME[$IP]
        else
            echo "$(date): IP $IP 失败 ${FAIL_COUNT[$IP]}/$MAX_RETRY" >> /var/log/ssh_ban.log
        fi
    fi
done
MONITOR_SCRIPT

chmod +x /usr/local/bin/ban_failed_ssh.sh

# ============================================
# 5. 创建 ban-manager 管理工具
# ============================================
print_header "创建管理工具"

cat > /usr/local/bin/ban-manager << 'MANAGER_TOOL'
#!/bin/bash

# ============================================
# SSH 防护管理工具 v4.0 - firewalld 版
# ============================================

IPSET_NAME="ssh_ban_set"
WHITELIST_FILE="/etc/ssh_ban_whitelist.conf"
BANNED_IPS_FILE="/etc/banned_ips.txt"
SSH_PORT=$(grep "^Port" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
[ -z "$SSH_PORT" ] && SSH_PORT=22

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

show_help() {
    echo -e "${BLUE}========================================="
    echo "SSH 防护系统 v4.0 (firewalld)"
    echo -e "=========================================${NC}"
    echo ""
    echo -e "${GREEN}📌 封禁管理:${NC}"
    echo "  ban-manager list              - 查看封禁IP列表"
    echo "  ban-manager status            - 查看状态"
    echo "  ban-manager stats             - 详细统计"
    echo "  ban-manager unban <IP>        - 解封IP"
    echo "  ban-manager clear             - 清空所有封禁"
    echo ""
    echo -e "${GREEN}⚪ 白名单管理:${NC}"
    echo "  ban-manager whitelist add <IP>    - 添加白名单"
    echo "  ban-manager whitelist remove <IP> - 移除白名单"
    echo "  ban-manager whitelist list        - 查看白名单"
    echo ""
    echo -e "${GREEN}💾 其他:${NC}"
    echo "  ban-manager test <IP>         - 测试IP状态"
    echo "  ban-manager export            - 导出封禁列表"
}

# 获取封禁数量
get_count() {
    firewall-cmd --ipset="$IPSET_NAME" --get-entries 2>/dev/null | wc -l
}

case "$1" in
    list)
        COUNT=$(get_count)
        echo -e "${BLUE}=========================================${NC}"
        echo -e "${GREEN}当前被封禁IP (共 $COUNT 个)${NC}"
        echo -e "${BLUE}=========================================${NC}"
        if [ $COUNT -gt 0 ]; then
            firewall-cmd --ipset="$IPSET_NAME" --get-entries 2>/dev/null | while read ip; do
                echo "  🔒 $ip"
            done
        else
            echo "  ✅ 暂无封禁"
        fi
        ;;

    status)
        COUNT=$(get_count)
        echo -e "${BLUE}=========================================${NC}"
        echo -e "${GREEN}封禁状态${NC}"
        echo -e "${BLUE}=========================================${NC}"
        echo -e "封禁IP数: ${RED}$COUNT${NC}"
        echo ""
        echo -e "${GREEN}最近5条封禁记录:${NC}"
        tail -5 /var/log/ssh_ban.log 2>/dev/null | sed 's/^/  /'
        ;;

    stats)
        COUNT=$(get_count)
        WHITE_COUNT=$(cat "$WHITELIST_FILE" 2>/dev/null | wc -l)
        TODAY=$(date +%b\ %d)
        TODAY_BAN=$(grep "封禁" /var/log/ssh_ban.log 2>/dev/null | grep "$TODAY" | wc -l)
        echo -e "${BLUE}=========================================${NC}"
        echo -e "${GREEN}详细统计${NC}"
        echo -e "${BLUE}=========================================${NC}"
        echo -e "🔒 当前封禁: $COUNT"
        echo -e "⚪ 白名单: $WHITE_COUNT"
        echo -e "📈 今日封禁: $TODAY_BAN"
        echo -e "📝 日志大小: $(du -h /var/log/ssh_ban.log 2>/dev/null | awk '{print $1}')"
        ;;

    unban)
        [ -z "$2" ] && { echo -e "${RED}用法: ban-manager unban <IP>${NC}"; exit 1; }
        firewall-cmd --permanent --ipset="$IPSET_NAME" --remove-entry="$2" 2>/dev/null
        firewall-cmd --reload
        sed -i "/^$2$/d" "$BANNED_IPS_FILE" 2>/dev/null
        echo -e "${GREEN}✅ 已解封 $2${NC}"
        ;;

    clear)
        echo -e "${RED}⚠️ 清空所有封禁？(y/n)${NC}"
        read confirm
        if [ "$confirm" = "y" ]; then
            firewall-cmd --permanent --ipset="$IPSET_NAME" --flush 2>/dev/null
            firewall-cmd --reload
            > "$BANNED_IPS_FILE" 2>/dev/null
            echo -e "${GREEN}✅ 已清空${NC}"
        fi
        ;;

    whitelist)
        case "$2" in
            add)
                [ -z "$3" ] && { echo -e "${RED}用法: ban-manager whitelist add <IP>${NC}"; exit 1; }
                echo "$3" >> "$WHITELIST_FILE"
                echo -e "${GREEN}✅ 已添加 $3 到白名单${NC}"
                ;;
            remove)
                [ -z "$3" ] && { echo -e "${RED}用法: ban-manager whitelist remove <IP>${NC}"; exit 1; }
                sed -i "/^$3$/d" "$WHITELIST_FILE" 2>/dev/null
                echo -e "${GREEN}✅ 已移除 $3${NC}"
                ;;
            list)
                echo -e "${BLUE}=========================================${NC}"
                echo -e "${GREEN}白名单列表${NC}"
                echo -e "${BLUE}=========================================${NC}"
                if [ -f "$WHITELIST_FILE" ] && [ -s "$WHITELIST_FILE" ]; then
                    cat "$WHITELIST_FILE" | while read ip; do
                        echo "  ⚪ $ip"
                    done
                else
                    echo "  (无)"
                fi
                ;;
            *)
                echo -e "${RED}用法: ban-manager whitelist {add|remove|list} [IP]${NC}"
                ;;
        esac
        ;;

    test)
        [ -z "$2" ] && { echo -e "${RED}用法: ban-manager test <IP>${NC}"; exit 1; }
        if firewall-cmd --ipset="$IPSET_NAME" --query-entry="$2" 2>/dev/null; then
            echo -e "${RED}❌ IP $2 已被封禁${NC}"
        else
            echo -e "${GREEN}✅ IP $2 未被封禁${NC}"
        fi
        ;;

    export)
        FILE="banned_ips_$(date +%Y%m%d_%H%M%S).txt"
        firewall-cmd --ipset="$IPSET_NAME" --get-entries 2>/dev/null > "$FILE"
        echo -e "${GREEN}✅ 已导出到 $FILE (共 $(wc -l < $FILE) 个)${NC}"
        ;;

    *)
        show_help
        ;;
esac
MANAGER_TOOL

chmod +x /usr/local/bin/ban-manager

# ============================================
# 6. 创建 systemd 服务
# ============================================
print_header "创建系统服务"

cat > /etc/systemd/system/ssh-ban.service << 'SERVICE'
[Unit]
Description=SSH Brute Force Protection (firewalld)
After=network.target firewalld.service sshd.service

[Service]
Type=simple
ExecStart=/usr/local/bin/ban_failed_ssh.sh
Restart=always
RestartSec=10
StandardOutput=append:/var/log/ssh_ban.log
StandardError=append:/var/log/ssh_ban.log

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable ssh-ban.service

# ============================================
# 7. 配置日志轮转
# ============================================
cat > /etc/logrotate.d/ssh-ban << 'LOGROTATE'
/var/log/ssh_ban.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0644 root root
    postrotate
        systemctl reload ssh-ban.service 2>/dev/null || true
    endscript
}
LOGROTATE

# ============================================
# 8. 创建白名单和封禁记录文件
# ============================================
touch /etc/ssh_ban_whitelist.conf
touch /etc/banned_ips.txt

# 添加本地IP到白名单
cat >> /etc/ssh_ban_whitelist.conf << 'EOF'
127.0.0.1
::1
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
EOF

# ============================================
# 9. 启动服务
# ============================================
print_header "启动服务"
systemctl restart ssh-ban.service

sleep 2

if systemctl is-active --quiet ssh-ban.service; then
    print_success "服务已启动"
else
    print_error "服务启动失败"
    systemctl status ssh-ban.service
    exit 1
fi

# ============================================
# 10. 显示完成信息
# ============================================
clear
print_header "✅ 安装完成 (firewalld 原生版)"

echo ""
echo -e "${YELLOW}📊 系统状态:${NC}"
echo -e "  服务: ${GREEN}$(systemctl is-active ssh-ban.service)${NC}"
echo -e "  封禁数: ${GREEN}$(firewall-cmd --ipset=ssh_ban_set --get-entries 2>/dev/null | wc -l)${NC}"
echo -e "  监控端口: ${GREEN}$SSH_PORT${NC}"
echo ""
echo -e "${YELLOW}🔧 常用命令:${NC}"
echo -e "  ${GREEN}ban-manager list${NC}        # 查看封禁列表"
echo -e "  ${GREEN}ban-manager status${NC}      # 查看状态"
echo -e "  ${GREEN}ban-manager stats${NC}       # 详细统计"
echo -e "  ${GREEN}ban-manager unban 1.2.3.4${NC}  # 解封IP"
echo -e "  ${GREEN}ban-manager whitelist add IP${NC}  # 添加白名单"
echo ""
echo -e "${YELLOW}📝 查看日志:${NC}"
echo -e "  ${GREEN}tail -f /var/log/ssh_ban.log${NC}"
echo ""
print_header "安装完成"
