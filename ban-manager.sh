#!/bin/bash
# ============================================
# SSH 暴力破解防护系统 - 一键安装脚本
# 版本: v3.0
# 功能: 多端口监控、IPv6支持、白名单、高性能封禁
# 作者: System Admin
# 日期: 2026-06-14
# ============================================

set -e  # 遇到错误立即退出

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 打印带颜色的消息
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo ""
    echo -e "${GREEN}=========================================${NC}"
    echo -e "${GREEN}$1${NC}"
    echo -e "${GREEN}=========================================${NC}"
}

# 检查是否为root用户
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "请使用root权限运行此脚本"
        echo "使用方法: sudo $0"
        exit 1
    fi
}

# 检测系统类型
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
    else
        print_error "无法检测系统类型"
        exit 1
    fi
    
    print_info "检测到系统: $OS $VER"
}

# 安装依赖包
install_dependencies() {
    print_header "安装依赖包"
    
    if command -v yum &>/dev/null; then
        # RHEL/CentOS/Rocky/AlmaLinux
        print_info "使用 yum 安装依赖..."
        yum install -y epel-release
        yum install -y iptables-services ipset mailx curl bc
        systemctl enable iptables
        systemctl start iptables
        
    elif command -v apt-get &>/dev/null; then
        # Ubuntu/Debian
        print_info "使用 apt-get 安装依赖..."
        apt-get update
        apt-get install -y iptables-persistent ipset mailutils curl bc
        systemctl enable netfilter-persistent 2>/dev/null || true
        
    elif command -v dnf &>/dev/null; then
        # Fedora
        print_info "使用 dnf 安装依赖..."
        dnf install -y iptables-services ipset mailx curl bc
        systemctl enable iptables
        
    else
        print_error "不支持的包管理器"
        exit 1
    fi
    
    print_success "依赖包安装完成"
}

# 创建监控脚本
create_monitor_script() {
    print_header "创建监控脚本"
    
    sudo tee /usr/local/bin/ban_failed_ssh.sh > /dev/null << 'MONITOR_SCRIPT'
#!/bin/bash

# ============================================
# SSH 防护系统 v3.0 - 核心监控脚本
# ============================================

# 配置文件路径
if [ -f /var/log/secure ]; then
    LOG_FILE="/var/log/secure"
elif [ -f /var/log/auth.log ]; then
    LOG_FILE="/var/log/auth.log"
else
    echo "错误：找不到 SSH 日志文件" >> /var/log/ssh_ban.log
    exit 1
fi

IPTABLES_CHAIN="SSH_BAN"
IPSET_NAME="ssh_ban_set"
MONITOR_PORTS_FILE="/etc/ssh_ban_ports.conf"
WHITELIST_FILE="/etc/ssh_ban_whitelist.conf"
BANNED_IPS_FILE="/etc/banned_ips.txt"
MAX_RETRY=5
FIND_TIME=86400  # 24小时
CLEANUP_INTERVAL=3600  # 清理间隔（秒）

# 默认 SSH 端口（自动检测）
DEFAULT_SSH_PORT=$(grep "^Port" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
[ -z "$DEFAULT_SSH_PORT" ] && DEFAULT_SSH_PORT=22

# 创建 ipset 集合（高性能封禁）
sudo ipset create $IPSET_NAME hash:ip hashsize 4096 maxelem 100000 2>/dev/null

# 创建 iptables 链
sudo iptables -N $IPTABLES_CHAIN 2>/dev/null
sudo ip6tables -N ${IPTABLES_CHAIN}_V6 2>/dev/null

# 检查是否存在，不存在则创建配置文件
[ -f "$WHITELIST_FILE" ] || sudo touch $WHITELIST_FILE
[ -f "$MONITOR_PORTS_FILE" ] || sudo touch $MONITOR_PORTS_FILE
[ -f "$BANNED_IPS_FILE" ] || sudo touch $BANNED_IPS_FILE

# 函数：检查 IP 是否在白名单中
is_whitelisted() {
    local ip=$1
    sudo grep -q "^$ip$" "$WHITELIST_FILE" 2>/dev/null
}

# 函数：添加端口到监控列表
add_port_to_iptables() {
    local port=$1
    
    if ! sudo iptables -C INPUT -p tcp --dport $port -j $IPTABLES_CHAIN 2>/dev/null; then
        sudo iptables -I INPUT -p tcp --dport $port -j $IPTABLES_CHAIN
        echo "$(date): 已添加端口 $port 到监控列表" >> /var/log/ssh_ban.log
    fi
    
    # IPv6 支持
    if ! sudo ip6tables -C INPUT -p tcp --dport $port -j ${IPTABLES_CHAIN}_V6 2>/dev/null; then
        sudo ip6tables -I INPUT -p tcp --dport $port -j ${IPTABLES_CHAIN}_V6
    fi
}

# 函数：初始化规则
init_rules() {
    # IPv4 规则
    if ! sudo iptables -C INPUT -p tcp --dport $DEFAULT_SSH_PORT -j $IPTABLES_CHAIN 2>/dev/null; then
        sudo iptables -I INPUT -p tcp --dport $DEFAULT_SSH_PORT -j $IPTABLES_CHAIN
    fi
    
    # 使用 ipset 的高性能规则
    if sudo ipset list $IPSET_NAME &>/dev/null; then
        if ! sudo iptables -C $IPTABLES_CHAIN -m set --match-set $IPSET_NAME src -j DROP 2>/dev/null; then
            sudo iptables -A $IPTABLES_CHAIN -m set --match-set $IPSET_NAME src -j DROP
        fi
    fi
    
    # IPv6 规则
    if ! sudo ip6tables -C INPUT -p tcp --dport $DEFAULT_SSH_PORT -j ${IPTABLES_CHAIN}_V6 2>/dev/null; then
        sudo ip6tables -I INPUT -p tcp --dport $DEFAULT_SSH_PORT -j ${IPTABLES_CHAIN}_V6
    fi
}

# 加载已保存的额外监控端口
load_extra_ports() {
    if [ -f "$MONITOR_PORTS_FILE" ]; then
        while IFS= read -r line; do
            [ -n "$line" ] && add_port_to_iptables $line
        done < "$MONITOR_PORTS_FILE"
    fi
}

# 函数：清理过期记录（防止内存泄漏）
cleanup_old_records() {
    local current_time=$(date +%s)
    local cleaned=0
    
    for ip in "${!FIRST_FAIL_TIME[@]}"; do
        if [ $((current_time - ${FIRST_FAIL_TIME[$ip]})) -gt $FIND_TIME ]; then
            unset FAIL_COUNT[$ip]
            unset FIRST_FAIL_TIME[$ip]
            ((cleaned++))
        fi
    done
    
    if [ $cleaned -gt 0 ]; then
        echo "$(date): 清理了 $cleaned 个过期记录" >> /var/log/ssh_ban.log
    fi
}

# 函数：发送告警
send_alert() {
    local ip=$1
    local port=$2
    local count=$3
    
    if [ -n "$ALERT_EMAIL" ] && command -v mail &>/dev/null; then
        echo -e "IP: $ip\n端口: $port\n失败次数: $count\n时间: $(date)\n主机: $(hostname)" | \
        mail -s "[SSH防护] 封禁通知 - $ip" $ALERT_EMAIL 2>/dev/null
    fi
}

# 关联数组存储失败次数和时间戳
declare -A FAIL_COUNT
declare -A FIRST_FAIL_TIME

# 初始化
init_rules
load_extra_ports

# 恢复已封禁的 IP
if [ -f "$BANNED_IPS_FILE" ]; then
    while IFS= read -r ip; do
        [ -n "$ip" ] && sudo ipset add $IPSET_NAME $ip 2>/dev/null
    done < "$BANNED_IPS_FILE"
    echo "$(date): 已恢复 $(wc -l < $BANNED_IPS_FILE) 个封禁 IP" >> /var/log/ssh_ban.log
fi

# 记录脚本启动
echo "$(date): SSH 封禁监控脚本 v3.0 已启动" >> /var/log/ssh_ban.log
echo "默认监控端口: $DEFAULT_SSH_PORT" >> /var/log/ssh_ban.log
echo "额外监控端口: $(cat $MONITOR_PORTS_FILE 2>/dev/null | tr '\n' ' ')" >> /var/log/ssh_ban.log

# 启动定期清理进程
(
    while true; do
        sleep $CLEANUP_INTERVAL
        cleanup_old_records
    done
) &

# 监控日志
tail -Fn0 $LOG_FILE | while read line; do
    # 匹配失败的 SSH 登录尝试
    if echo "$line" | grep -q "Failed password"; then
        # 提取 IP (IPv4 和 IPv6)
        IP=$(echo "$line" | grep -oP 'from \K[0-9.]+' || echo "$line" | grep -oP 'from (::[0-9a-f:]+)' | awk '{print $2}')
        
        # 提取端口
        PORT=$(echo "$line" | grep -oP 'port \K[0-9]+' | head -1)
        
        # 检查是否有效 IP
        [ -z "$IP" ] && continue
        
        # 检查白名单
        if is_whitelisted "$IP"; then
            echo "$(date): IP $IP 在白名单中，跳过封禁" >> /var/log/ssh_ban.log
            continue
        fi
        
        # 检查是否已经封禁
        if sudo ipset test $IPSET_NAME $IP 2>/dev/null; then
            continue
        fi
        
        CURRENT_TIME=$(date +%s)
        
        # 初始化或获取该 IP 的失败记录
        if [ -z "${FIRST_FAIL_TIME[$IP]}" ]; then
            FIRST_FAIL_TIME[$IP]=$CURRENT_TIME
            FAIL_COUNT[$IP]=1
        else
            # 检查是否还在时间窗口内
            TIME_DIFF=$((CURRENT_TIME - ${FIRST_FAIL_TIME[$IP]}))
            if [ $TIME_DIFF -le $FIND_TIME ]; then
                FAIL_COUNT[$IP]=$((${FAIL_COUNT[$IP]} + 1))
            else
                # 超过时间窗口，重置计数
                FIRST_FAIL_TIME[$IP]=$CURRENT_TIME
                FAIL_COUNT[$IP]=1
            fi
        fi
        
        # 检查是否达到封禁阈值
        if [ ${FAIL_COUNT[$IP]} -ge $MAX_RETRY ]; then
            # 使用 ipset 永久封禁 IP（高性能）
            sudo ipset add $IPSET_NAME $IP 2>/dev/null
            
            echo "$(date): 🔒 封禁 IP $IP (端口: $PORT, 失败 ${FAIL_COUNT[$IP]} 次)" | tee -a /var/log/ssh_ban.log
            
            # 记录到持久化文件
            echo "$IP" | sudo tee -a $BANNED_IPS_FILE > /dev/null
            
            # 发送告警（如果配置了邮箱）
            [ -n "$ALERT_EMAIL" ] && send_alert "$IP" "$PORT" "${FAIL_COUNT[$IP]}"
            
            # 清理数组记录
            unset FAIL_COUNT[$IP]
            unset FIRST_FAIL_TIME[$IP]
        else
            echo "$(date): IP $IP 失败次数 ${FAIL_COUNT[$IP]}/$MAX_RETRY (端口: $PORT)" >> /var/log/ssh_ban.log
        fi
    fi
done
MONITOR_SCRIPT

    sudo chmod +x /usr/local/bin/ban_failed_ssh.sh
    print_success "监控脚本创建完成"
}

# 创建管理工具
create_manager_tool() {
    print_header "创建管理工具"
    
    sudo tee /usr/local/bin/ban-manager > /dev/null << 'MANAGER_TOOL'
#!/bin/bash

# ============================================
# SSH 防护管理系统 v3.0 - 管理工具
# ============================================

IPTABLES_CHAIN="SSH_BAN"
IPSET_NAME="ssh_ban_set"
MONITOR_PORTS_FILE="/etc/ssh_ban_ports.conf"
WHITELIST_FILE="/etc/ssh_ban_whitelist.conf"
BANNED_IPS_FILE="/etc/banned_ips.txt"
DEFAULT_SSH_PORT=$(grep "^Port" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
[ -z "$DEFAULT_SSH_PORT" ] && DEFAULT_SSH_PORT=22

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 函数：获取当前监控的端口
get_monitored_ports() {
    sudo iptables -L INPUT -n | grep "$IPTABLES_CHAIN" | grep -oP 'dpt:\K[0-9]+' | sort -n | uniq
}

# 函数：获取封禁IP数量
get_banned_count() {
    sudo ipset list $IPSET_NAME 2>/dev/null | grep -c "^[0-9a-f.:]" || echo 0
}

# 确保资源存在
ensure_resources() {
    sudo ipset create $IPSET_NAME hash:ip hashsize 4096 maxelem 100000 2>/dev/null
    sudo iptables -N $IPTABLES_CHAIN 2>/dev/null
    sudo ip6tables -N ${IPTABLES_CHAIN}_V6 2>/dev/null
    
    if ! sudo iptables -C $IPTABLES_CHAIN -m set --match-set $IPSET_NAME src -j DROP 2>/dev/null; then
        sudo iptables -A $IPTABLES_CHAIN -m set --match-set $IPSET_NAME src -j DROP
    fi
}

ensure_resources

# 显示帮助
show_help() {
    echo -e "${BLUE}========================================="
    echo "SSH 防护管理系统 v3.0"
    echo -e "=========================================${NC}"
    echo ""
    echo -e "${GREEN}📌 基础命令:${NC}"
    echo "  ban-manager list              - 查看封禁IP列表"
    echo "  ban-manager status            - 查看封禁状态"
    echo "  ban-manager stats             - 显示详细统计"
    echo "  ban-manager unban <IP>        - 解封指定IP"
    echo "  ban-manager clear             - 清空所有封禁IP"
    echo ""
    echo -e "${GREEN}➕ 端口管理:${NC}"
    echo "  ban-manager add-port <端口>   - 添加监控端口"
    echo "  ban-manager remove-port <端口>- 移除监控端口"
    echo "  ban-manager ports             - 查看监控端口"
    echo ""
    echo -e "${GREEN}⚪ 白名单管理:${NC}"
    echo "  ban-manager whitelist add <IP>    - 添加白名单"
    echo "  ban-manager whitelist remove <IP> - 移除白名单"
    echo "  ban-manager whitelist list        - 查看白名单"
    echo ""
    echo -e "${GREEN}💾 其他命令:${NC}"
    echo "  ban-manager save              - 保存规则"
    echo "  ban-manager test <IP>         - 测试IP状态"
    echo "  ban-manager export            - 导出封禁列表"
    echo ""
}

case "$1" in
    list)
        echo -e "${BLUE}=========================================${NC}"
        echo -e "${GREEN}当前被封禁的IP列表：${NC}"
        echo -e "${BLUE}=========================================${NC}"
        BANNED_COUNT=$(get_banned_count)
        if [ $BANNED_COUNT -gt 0 ]; then
            sudo ipset list $IPSET_NAME | grep -E "^[0-9a-f.:]+$" | head -20 | while read ip; do
                echo "  🔒 $ip"
            done
            if [ $BANNED_COUNT -gt 20 ]; then
                echo "  ... 还有 $((BANNED_COUNT - 20)) 个IP"
            fi
            echo ""
            echo "总计: $BANNED_COUNT 个IP"
        else
            echo "  ✅ 暂无封禁IP"
        fi
        ;;
    
    status)
        COUNT=$(get_banned_count)
        echo -e "${BLUE}=========================================${NC}"
        echo -e "${GREEN}封禁状态统计${NC}"
        echo -e "${BLUE}=========================================${NC}"
        echo -e "封禁IP数量: ${RED}$COUNT${NC}"
        echo ""
        if [ -f /var/log/ssh_ban.log ]; then
            echo -e "${GREEN}最近10条封禁记录:${NC}"
            tail -10 /var/log/ssh_ban.log | sed 's/^/  /'
        fi
        ;;
    
    stats)
        COUNT=$(get_banned_count)
        echo -e "${BLUE}=========================================${NC}"
        echo -e "${GREEN}详细统计信息${NC}"
        echo -e "${BLUE}=========================================${NC}"
        echo -e "📊 封禁IP总数: ${RED}$COUNT${NC}"
        echo -e "🔧 监控端口数: $(get_monitored_ports | wc -l)"
        echo -e "⚪ 白名单IP数: $(cat $WHITELIST_FILE 2>/dev/null | wc -l)"
        echo -e "📝 日志大小: $(du -h /var/log/ssh_ban.log 2>/dev/null | awk '{print $1}')"
        
        # 显示今日封禁数
        TODAY=$(date +%b\ %d)
        TODAY_BAN=$(grep "封禁 IP" /var/log/ssh_ban.log 2>/dev/null | grep "$TODAY" | wc -l)
        echo -e "📈 今日封禁: ${YELLOW}$TODAY_BAN${NC} 次"
        ;;
    
    unban)
        if [ -z "$2" ]; then
            echo -e "${RED}用法: ban-manager unban <IP地址>${NC}"
            exit 1
        fi
        sudo ipset del $IPSET_NAME $2 2>/dev/null
        sudo sed -i "/^$2$/d" $BANNED_IPS_FILE 2>/dev/null
        echo -e "${GREEN}✅ 已解封 IP: $2${NC}"
        ;;
    
    add-port)
        if [ -z "$2" ]; then
            echo -e "${RED}用法: ban-manager add-port <端口号>${NC}"
            exit 1
        fi
        if ! [[ "$2" =~ ^[0-9]+$ ]] || [ "$2" -lt 1 ] || [ "$2" -gt 65535 ]; then
            echo -e "${RED}❌ 无效端口号${NC}"
            exit 1
        fi
        if sudo iptables -C INPUT -p tcp --dport $2 -j $IPTABLES_CHAIN 2>/dev/null; then
            echo -e "${YELLOW}⚠️  端口 $2 已在监控中${NC}"
            exit 0
        fi
        sudo iptables -I INPUT -p tcp --dport $2 -j $IPTABLES_CHAIN
        echo "$2" | sudo tee -a $MONITOR_PORTS_FILE > /dev/null
        echo -e "${GREEN}✅ 已添加端口 $2 到监控列表${NC}"
        ;;
    
    remove-port)
        if [ -z "$2" ]; then
            echo -e "${RED}用法: ban-manager remove-port <端口号>${NC}"
            exit 1
        fi
        if [ "$2" = "$DEFAULT_SSH_PORT" ]; then
            echo -e "${RED}⚠️  不能移除默认 SSH 端口${NC}"
            exit 1
        fi
        sudo iptables -D INPUT -p tcp --dport $2 -j $IPTABLES_CHAIN 2>/dev/null
        sudo sed -i "/^$2$/d" $MONITOR_PORTS_FILE 2>/dev/null
        echo -e "${GREEN}✅ 已移除端口 $2${NC}"
        ;;
    
    ports)
        echo -e "${BLUE}=========================================${NC}"
        echo -e "${GREEN}当前监控端口${NC}"
        echo -e "${BLUE}=========================================${NC}"
        echo -e "${YELLOW}🔒 默认端口: $DEFAULT_SSH_PORT${NC}"
        echo ""
        echo -e "${GREEN}额外端口:${NC}"
        EXTRA_PORTS=$(get_monitored_ports | grep -v "^$DEFAULT_SSH_PORT$")
        if [ -n "$EXTRA_PORTS" ]; then
            for port in $EXTRA_PORTS; do
                echo "  - $port"
            done
        else
            echo "  (无)"
        fi
        ;;
    
    whitelist)
        case "$2" in
            add)
                [ -z "$3" ] && { echo -e "${RED}用法: ban-manager whitelist add <IP>${NC}"; exit 1; }
                echo "$3" | sudo tee -a $WHITELIST_FILE > /dev/null
                echo -e "${GREEN}✅ 已添加 $3 到白名单${NC}"
                ;;
            remove)
                [ -z "$3" ] && { echo -e "${RED}用法: ban-manager whitelist remove <IP>${NC}"; exit 1; }
                sudo sed -i "/^$3$/d" $WHITELIST_FILE 2>/dev/null
                echo -e "${GREEN}✅ 已从白名单移除 $3${NC}"
                ;;
            list)
                echo -e "${BLUE}=========================================${NC}"
                echo -e "${GREEN}白名单IP列表${NC}"
                echo -e "${BLUE}=========================================${NC}"
                if [ -f "$WHITELIST_FILE" ] && [ -s "$WHITELIST_FILE" ]; then
                    cat $WHITELIST_FILE | while read ip; do
                        echo "  ⚪ $ip"
                    done
                else
                    echo "  (无)"
                fi
                ;;
            *)
                echo -e "${RED}用法: ban-manager whitelist {add|remove|list} [IP]${NC}"
                exit 1
                ;;
        esac
        ;;
    
    clear)
        echo -e "${RED}⚠️  清空所有封禁IP？(y/n)${NC}"
        read -r confirm
        if [ "$confirm" = "y" ]; then
            sudo ipset flush $IPSET_NAME
            sudo > $BANNED_IPS_FILE
            echo -e "${GREEN}✅ 已清空所有封禁IP${NC}"
        fi
        ;;
    
    save)
        echo -e "${YELLOW}正在保存规则...${NC}"
        if command -v iptables-save &> /dev/null; then
            if [ -f /etc/redhat-release ]; then
                service iptables save 2>/dev/null
            else
                iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
            fi
            ipset save $IPSET_NAME > /etc/ipset.conf 2>/dev/null
            echo -e "${GREEN}✅ 规则已保存${NC}"
        fi
        ;;
    
    test)
        [ -z "$2" ] && { echo -e "${RED}用法: ban-manager test <IP>${NC}"; exit 1; }
        if sudo ipset test $IPSET_NAME $2 2>/dev/null; then
            echo -e "${RED}❌ IP $2 已被封禁${NC}"
        else
            echo -e "${GREEN}✅ IP $2 未被封禁${NC}"
        fi
        ;;
    
    export)
        FILE="banned_ips_$(date +%Y%m%d_%H%M%S).txt"
        sudo ipset list $IPSET_NAME | grep -E "^[0-9a-f.:]+$" > $FILE
        echo -e "${GREEN}✅ 已导出到 $FILE${NC}"
        ;;
    
    *)
        show_help
        exit 1
        ;;
esac
MANAGER_TOOL

    sudo chmod +x /usr/local/bin/ban-manager
    print_success "管理工具创建完成"
}

# 创建 systemd 服务
create_systemd_service() {
    print_header "创建系统服务"
    
    sudo tee /etc/systemd/system/ssh-ban.service > /dev/null << 'SERVICE_FILE'
[Unit]
Description=SSH Brute Force Protection Service
After=network.target sshd.service
Before=iptables.service

[Service]
Type=simple
ExecStart=/usr/local/bin/ban_failed_ssh.sh
Restart=always
RestartSec=10
StandardOutput=append:/var/log/ssh_ban.log
StandardError=append:/var/log/ssh_ban.log

[Install]
WantedBy=multi-user.target
SERVICE_FILE

    sudo systemctl daemon-reload
    sudo systemctl enable ssh-ban.service
    print_success "系统服务创建完成"
}

# 配置日志轮转
configure_logrotate() {
    print_header "配置日志轮转"
    
    sudo tee /etc/logrotate.d/ssh-ban > /dev/null << 'LOGROTATE'
/var/log/ssh_ban.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0644 root root
    postrotate
        systemctl reload ssh-ban.service > /dev/null 2>&1 || true
    endscript
}
LOGROTATE
    
    print_success "日志轮转配置完成"
}

# 初始化配置
init_config() {
    print_header "初始化配置"
    
    # 创建配置文件
    sudo touch /etc/ssh_ban_whitelist.conf
    sudo touch /etc/ssh_ban_ports.conf
    sudo touch /etc/banned_ips.txt
    
    # 添加本地IP到白名单
    print_info "是否添加本地网络到白名单？(y/n)"
    read -r add_local
    if [ "$add_local" = "y" ]; then
        echo "127.0.0.1" | sudo tee -a /etc/ssh_ban_whitelist.conf > /dev/null
        echo "::1" | sudo tee -a /etc/ssh_ban_whitelist.conf > /dev/null
        echo "10.0.0.0/8" | sudo tee -a /etc/ssh_ban_whitelist.conf > /dev/null
        echo "172.16.0.0/12" | sudo tee -a /etc/ssh_ban_whitelist.conf > /dev/null
        echo "192.168.0.0/16" | sudo tee -a /etc/ssh_ban_whitelist.conf > /dev/null
        print_success "已添加本地网络到白名单"
    fi
    
    # 配置邮件告警
    print_info "是否配置邮件告警？(y/n)"
    read -r config_email
    if [ "$config_email" = "y" ]; then
        echo -n "请输入邮箱地址: "
        read -r email
        echo "export ALERT_EMAIL=$email" | sudo tee -a /etc/profile.d/ssh-ban.sh > /dev/null
        print_success "邮件告警已配置: $email"
    fi
}

# 启动服务
start_service() {
    print_header "启动服务"
    
    sudo systemctl start ssh-ban.service
    
    sleep 2
    
    if systemctl is-active --quiet ssh-ban.service; then
        print_success "服务已启动"
    else
        print_error "服务启动失败"
        systemctl status ssh-ban.service
        exit 1
    fi
}

# 显示完成信息
show_completion() {
    clear
    print_header "✅ SSH 防护系统安装完成！"
    
    echo ""
    echo -e "${YELLOW}📊 系统状态:${NC}"
    echo -e "  服务状态: ${GREEN}$(systemctl is-active ssh-ban.service)${NC}"
    echo -e "  封禁IP数: ${GREEN}$(sudo ipset list ssh_ban_set 2>/dev/null | grep -c "^[0-9]" || echo 0)${NC}"
    echo ""
    echo -e "${YELLOW}🔧 常用命令:${NC}"
    echo -e "  ${GREEN}ban-manager list${NC}        # 查看封禁列表"
    echo -e "  ${GREEN}ban-manager status${NC}      # 查看状态"
    echo -e "  ${GREEN}ban-manager stats${NC}       # 详细统计"
    echo -e "  ${GREEN}ban-manager ports${NC}       # 查看监控端口"
    echo -e "  ${GREEN}ban-manager add-port 2222${NC}  # 添加监控端口"
    echo -e "  ${GREEN}ban-manager whitelist add IP${NC}  # 添加白名单"
    echo -e "  ${GREEN}ban-manager unban IP${NC}    # 解封IP"
    echo ""
    echo -e "${YELLOW}📝 日志查看:${NC}"
    echo -e "  ${GREEN}tail -f /var/log/ssh_ban.log${NC}"
    echo ""
    echo -e "${YELLOW}💡 配置说明:${NC}"
    echo -e "  1. 修改封禁阈值: 编辑 ${BLUE}/usr/local/bin/ban_failed_ssh.sh${NC}"
    echo -e "  2. 修改 MAX_RETRY=5 为需要的次数"
    echo -e "  3. 重启服务: ${GREEN}systemctl restart ssh-ban${NC}"
    echo ""
    print_header "安装完成"
}

# 主函数
main() {
    print_header "SSH 暴力破解防护系统安装脚本"
    echo ""
    print_warning "此脚本将安装 SSH 防护系统，包括："
    echo "  - 实时监控 SSH 登录失败"
    echo "  - 自动封禁暴力破解 IP"
    echo "  - 支持多端口监控"
    echo "  - 白名单机制"
    echo "  - 邮件告警"
    echo ""
    
    read -p "是否继续安装？(y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "安装已取消"
        exit 0
    fi
    
    check_root
    detect_os
    install_dependencies
    create_monitor_script
    create_manager_tool
    create_systemd_service
    configure_logrotate
    init_config
    start_service
    show_completion
}

# 执行主函数
main
