#!/bin/sh
# =============================================================================
#  VMProbe 协从端引导脚本（POSIX sh，单文件，无需任何解释器依赖）
#
#  用途：在任意 Linux 发行版上探测环境、落地并安装 vmprobe 二进制。
#        不假设远端有 python / node / curl / wget —— 二进制由主控端经 SFTP 推送。
#
#  用法：
#    sh bootstrap.sh --check                      仅探测并输出 facts JSON（只读，绝不写盘）
#    sh bootstrap.sh --install <src> --sha256 X   安装（**默认强制校验**完整性）
#    sh bootstrap.sh --install <src> --no-verify  安装但跳过校验（不推荐，需显式写出）
#    sh bootstrap.sh --uninstall [--purge]        卸载（--purge 连日志一起删）
#    sh bootstrap.sh --selfcheck                  自检：版本 / 权限 / 可写目录
#
#  设计要点（见 DESIGN.md §5.1）：
#    · 所有探测项独立容错，任一缺失只记 null，绝不整体失败；
#    · --check 是纯只读的，可以在任何目标上安全运行；
#    · 安装目录三级降级：系统级 → 用户级 → /dev/shm（并明确告知不持久）；
#    · 校验 sha256 后才落地，避免被中间篡改的二进制。
# =============================================================================

set -u

VMPROBE_PROBE_VERSION=1
VMPROBE_AGENT_VERSION="0.1.0-m0"
SYS_DIR=/usr/local/lib/vmprobe
SYS_BIN=/usr/local/bin/vmprobe
LOG_DIR=/var/log/vmprobe

# ---------------------------------------------------------------------------
# 小工具
# ---------------------------------------------------------------------------

# JSON 字符串转义。
#
# 注意：facts 的值来自**被控机上的文件**（如 /etc/os-release），属于不可信输入 ——
# 只转义反斜杠和引号是不够的，换行与控制字符会让整个 JSON 非法。
# 这里先剥掉所有 C0 控制字符与 DEL，再转义 \\ 和 "。
json_escape() {
    printf '%s' "$1" | tr -d '\000-\037\177' | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

# 输出 JSON 字段：jq_str key value
jq_str() {
    printf '    "%s": "%s"' "$1" "$(json_escape "${2}")"
}

have() { command -v "$1" >/dev/null 2>&1; }

# 读 os-release 的一个键（去引号）
#
# 路径可用 `VMPROBE_OS_RELEASE` 覆盖：绝大多数系统有 /etc/os-release，
# 但极简容器与自定义根目录可能没有；测试台也靠它注入假发行版以覆盖发行版分支。
os_release_value() {
    osr="${VMPROBE_OS_RELEASE:-/etc/os-release}"
    [ -r "$osr" ] || return 1
    val=$(sed -n "s/^$1=//p" "$osr" | head -n 1)
    [ -n "$val" ] || return 1
    # 去掉首尾引号
    val=$(printf '%s' "$val" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//")
    printf '%s' "$val"
}

# ---------------------------------------------------------------------------
# 探测
# ---------------------------------------------------------------------------

detect_arch() {
    m=$(uname -m 2>/dev/null || printf 'unknown')
    case "$m" in
        x86_64|amd64)   printf 'amd64' ;;
        aarch64|arm64)  printf 'arm64' ;;
        armv7l|armv7)   printf 'armv7' ;;
        riscv64)        printf 'riscv64' ;;
        i386|i686)      printf '386' ;;
        *)              printf '%s' "$m" ;;
    esac
}

detect_libc() {
    if [ -e /lib/ld-musl-x86_64.so.1 ] || [ -e /lib/ld-musl-aarch64.so.1 ]; then
        printf 'musl'
        return
    fi
    if have ldd; then
        if ldd --version 2>&1 | head -n 1 | grep -qi musl; then
            printf 'musl'
            return
        fi
        printf 'glibc'
        return
    fi
    printf 'unknown'
}

detect_init() {
    comm=""
    [ -r /proc/1/comm ] && comm=$(cat /proc/1/comm 2>/dev/null)
    case "$comm" in
        systemd)  printf 'systemd' ;;
        init)     have openrc && printf 'openrc' || printf 'sysvinit' ;;
        runit*)   printf 'runit' ;;
        "")       # 容器里 /proc/1/comm 可能是应用名，退回特征探测
                  if have systemctl; then printf 'systemd'
                  elif have rc-service; then printf 'openrc'
                  else printf 'unknown'; fi ;;
        *)        printf '%s' "$comm" ;;
    esac
}

detect_is_container() {
    if [ -f /.dockerenv ]; then printf 'docker'; return; fi
    if [ -f /run/.containerenv ]; then printf 'podman'; return; fi
    if grep -qE '(docker|containerd|lxc|kubepods)' /proc/1/cgroup 2>/dev/null; then
        printf 'container'
        return
    fi
    printf 'none'
}

detect_virt() {
    if have systemd-detect-virt; then
        systemd-detect-virt 2>/dev/null || printf 'none'
        return
    fi
    if grep -qE '^flags.*(hypervisor)' /proc/cpuinfo 2>/dev/null; then
        printf 'vm'
        return
    fi
    printf 'none'
}

# 包管理器：输出空格分隔的可用列表 + 默认项
detect_pkgs() {
    list=""
    for pm in apt-get dnf yum zypper pacman apk; do
        if have "$pm"; then
            list="$list $pm"
        fi
    done
    printf '%s' "$(printf '%s' "$list" | sed 's/^ //')"
}

detect_default_pm() {
    for pm in apt-get dnf zypper pacman apk yum; do
        have "$pm" && { printf '%s' "$pm"; return; }
    done
    printf ''
}

# 包状态：**一次查询产出三个值** —— "可升级数 安全更新数 内核待升级数"。
#
# 为什么要合并成一次：原来只查可升级数，而安全更新数与"是否含内核升级"要再查两遍，
# 在真实机器上每次查询都是秒级（apt/dnf 要读元数据）。而且**内核标志是风险提权的依据**
# （含内核 → 动作从 R1 提升为 R2 并要求确认），所以它必须存在、且不能靠猜。
#
# 任一字段无法判定时输出**空**（上层记 null），绝不填 0 ——
# 0 会被读成"没有待更新"，即谎报一个更安全的状态。
detect_pkg_state() {
    if have apt-get; then
        sim=$(apt-get -s -o Debug::NoLocking=true upgrade 2>/dev/null) || { printf '  '; return; }
        n=$(printf '%s\n' "$sim" | grep -c '^Inst ' || true)
        k=$(printf '%s\n' "$sim" | grep -cE '^Inst +(linux-image|linux-generic|linux-headers|linux-modules|linux-virtual|linux-aws|linux-azure)' || true)
        # 安全更新数：apt 的模拟输出不带仓库来源，改用 apt list --upgradable 里的套件名（如 noble-security）
        sec=''
        if have apt; then
            lst=$(apt list --upgradable 2>/dev/null || true)
            if [ -n "$lst" ]; then
                sec=$(printf '%s\n' "$lst" | grep -c -- '-security' || true)
            fi
        fi
        printf '%s %s %s' "${n:-0}" "${sec:-}" "${k:-0}"
        return
    fi
    if have dnf; then
        out=$(dnf -q check-update 2>/dev/null)
        rc=$?
        # dnf check-update：0 = 无更新，100 = 有更新，其余为错误
        if [ "$rc" -ne 0 ] && [ "$rc" -ne 100 ]; then printf '  '; return; fi
        n=$(printf '%s\n' "$out" | grep -cE '^[a-zA-Z0-9]' || true)
        sec=$(printf '%s\n' "$out" | grep -ci 'security' || true)
        k=$(printf '%s\n' "$out" | grep -cE '^kernel' || true)
        printf '%s %s %s' "${n:-0}" "${sec:-}" "${k:-0}"
        return
    fi
    printf '  '
}

detect_reboot_required() {
    [ -f /var/run/reboot-required ] && { printf 'true'; return; }
    [ -f /run/reboot-required ] && { printf 'true'; return; }
    printf 'false'
}

detect_ssh_state() {
    # 输出 "pubkey password port"（无法判定时用 -）
    pk='-'; pw='-'; port='22'
    if [ -r /etc/ssh/sshd_config ]; then
        if grep -qiE '^[[:space:]]*PubkeyAuthentication[[:space:]]+no' /etc/ssh/sshd_config; then
            pk='false'
        elif grep -qiE '^[[:space:]]*PubkeyAuthentication[[:space:]]+yes' /etc/ssh/sshd_config; then
            pk='true'
        else
            pk='true'   # OpenSSH 默认开启
        fi
        if grep -qiE '^[[:space:]]*PasswordAuthentication[[:space:]]+no' /etc/ssh/sshd_config; then
            pw='false'
        elif grep -qiE '^[[:space:]]*PasswordAuthentication[[:space:]]+yes' /etc/ssh/sshd_config; then
            pw='true'
        fi
        p=$(grep -iE '^[[:space:]]*Port[[:space:]]+[0-9]+' /etc/ssh/sshd_config | head -n 1 | awk '{print $2}')
        [ -n "${p:-}" ] && port="$p"
    fi
    printf '%s %s %s' "$pk" "$pw" "$port"
}

have_root() {
    [ "$(id -u 2>/dev/null || printf 1)" = "0" ] && printf 'true' || printf 'false'
}

have_sudo() {
    have sudo && printf 'true' || printf 'false'
}

# ---------------------------------------------------------------------------
# 负载与硬件采集（日报的指标来源）
#
# 全部走 /proc 与 df —— 不依赖 nproc/awk/free/lscpu 这些"可能不存在"的工具。
# 取不到就输出空，由 emit_facts 转成 JSON null：**绝不填 0**，
# 因为 0 会被读成"负载为零/没有待更新"这类更安全的假象。
# ---------------------------------------------------------------------------

# 输出 "load1 load5 load15"，取不到则空
detect_load() {
    [ -r /proc/loadavg ] || return 0
    set -- $(sed -n '1p' /proc/loadavg 2>/dev/null)
    # 只接受形如数字的字段，避免把 "-" 之类的怪值当数字用
    case "${1:-}" in ''|*[!0-9.]*) return 0 ;; esac
    printf '%s %s %s' "${1:-}" "${2:-}" "${3:-}"
}

# 输出开机时长（秒），取不到则空
detect_uptime() {
    [ -r /proc/uptime ] || return 0
    set -- $(sed -n '1p' /proc/uptime 2>/dev/null)
    case "${1:-}" in ''|*[!0-9.]*) return 0 ;; esac
    # 取整数部分
    printf '%s' "${1%%.*}"
}

# 输出 CPU 核数，取不到则空
detect_cores() {
    if [ -r /proc/cpuinfo ]; then
        n=$(grep -c '^processor' /proc/cpuinfo 2>/dev/null || true)
        case "${n:-}" in ''|0) : ;; *) printf '%s' "$n"; return 0 ;; esac
    fi
    if have nproc; then
        n=$(nproc 2>/dev/null || true)
        case "${n:-}" in ''|*[!0-9]*) : ;; *) printf '%s' "$n" ;; esac
    fi
}

# 读 /proc/meminfo 的一个键，输出 kB 数值；取不到则空
meminfo_kb() {
    [ -r /proc/meminfo ] || return 0
    sed -n "s/^$1:[[:space:]]*\([0-9][0-9]*\).*/\1/p" /proc/meminfo 2>/dev/null | head -n 1
}

# 输出根分区 "sizeMb usedPct"，取不到则空
detect_root_disk() {
    have df || return 0
    line=$(df -Pk / 2>/dev/null | sed -n '2p')
    [ -n "$line" ] || return 0
    set -- $line
    size_kb="${2:-}"
    cap="${5:-}"
    case "$size_kb" in ''|*[!0-9]*) return 0 ;; esac
    size_mb=$((size_kb / 1024))
    # "44%" → 44
    cap_num=$(printf '%s' "$cap" | sed -e 's/%$//' -e 's/[^0-9]//g')
    [ -n "$cap_num" ] || return 0
    printf '%s %s' "$size_mb" "$cap_num"
}

# 可写性探测：三级降级
pick_install_dir() {
    if [ "$(id -u 2>/dev/null || printf 1)" = "0" ]; then
        printf '%s system' "$SYS_DIR"
        return
    fi
    if [ -w /usr/local/lib ] 2>/dev/null; then
        printf '%s system-userwritable' "$SYS_DIR"
        return
    fi
    home="${HOME:-/tmp}"
    if [ -w "$home" ] 2>/dev/null; then
        printf '%s user' "$home/.local/lib/vmprobe"
        return
    fi
    if [ -w /dev/shm ] 2>/dev/null; then
        printf '%s volatile' "/dev/shm/vmprobe"
        return
    fi
    printf '%s none' ""
}

# ---------------------------------------------------------------------------
# facts JSON
# ---------------------------------------------------------------------------

emit_facts() {
    arch=$(detect_arch)
    libc=$(detect_libc)
    init=$(detect_init)
    container=$(detect_is_container)
    virt=$(detect_virt)
    pms=$(detect_pkgs)
    dpm=$(detect_default_pm)
    pkg_state=$(detect_pkg_state)
    upgradable=''; security_up=''; kernel_pending=''
    if [ -n "$pkg_state" ]; then
        set -- $pkg_state
        upgradable="${1:-}"; security_up="${2:-}"; kernel_pending="${3:-}"
    fi
    reboot=$(detect_reboot_required)

    # 负载/硬件：先全部取成普通变量，再统一发 JSON。
    # 注意不能边取边 set --（会互相覆盖位置参数）。
    load_v=$(detect_load)
    uptime_v=$(detect_uptime)
    cores_v=$(detect_cores)
    mem_total_kb=$(meminfo_kb MemTotal)
    mem_avail_kb=$(meminfo_kb MemAvailable)
    [ -n "$mem_avail_kb" ] || mem_avail_kb=$(meminfo_kb MemFree)
    disk_v=$(detect_root_disk)

    load1=''; load5=''; load15=''
    if [ -n "$load_v" ]; then
        set -- $load_v
        load1="${1:-}"; load5="${2:-}"; load15="${3:-}"
    fi
    mem_total_mb=''; mem_avail_mb=''
    case "${mem_total_kb:-}" in ''|*[!0-9]*) : ;; *) mem_total_mb=$((mem_total_kb / 1024)) ;; esac
    case "${mem_avail_kb:-}" in ''|*[!0-9]*) : ;; *) mem_avail_mb=$((mem_avail_kb / 1024)) ;; esac
    disk_size_mb=''; disk_used_pct=''
    if [ -n "$disk_v" ]; then
        set -- $disk_v
        disk_size_mb="${1:-}"; disk_used_pct="${2:-}"
    fi

    set -- $(detect_ssh_state)
    pk="${1:--}"; pw="${2:--}"; sport="${3:-22}"
    root=$(have_root)
    sudo_ok=$(have_sudo)

    os_id=$(os_release_value ID 2>/dev/null || printf '')
    os_like=$(os_release_value ID_LIKE 2>/dev/null || printf '')
    os_ver=$(os_release_value VERSION_ID 2>/dev/null || printf '')
    os_pretty=$(os_release_value PRETTY_NAME 2>/dev/null || printf '')
    hostname_v=$(hostname 2>/dev/null || printf '')

    set -- $(pick_install_dir)
    idir="$1"; imode="${2:-none}"

    printf '{\n'
    printf '  "schema": "vmprobe/facts/%s",\n' "$VMPROBE_PROBE_VERSION"
    printf '  "probeVersion": %s,\n' "$VMPROBE_PROBE_VERSION"
    printf '  "host": {\n'
    jq_str hostname "$hostname_v"; printf ',\n'
    jq_str kernel "$(uname -r 2>/dev/null || printf '')"; printf '\n  },\n'
    printf '  "os": {\n'
    jq_str id "$os_id"; printf ',\n'
    # ID_LIKE 在 os-release 里是空格分隔字符串，但语义上是列表 —— 这里就发成数组，
    # 免得每个消费方各自解析（曾有消费方把它当数组用，直接崩）
    printf '    "idLike": ['
    first_like=1
    for w in $os_like; do
        if [ "$first_like" -eq 1 ]; then first_like=0; else printf ', '; fi
        printf '"%s"' "$(json_escape "$w")"
    done
    printf '],\n'
    jq_str versionId "$os_ver"; printf ',\n'
    jq_str prettyName "$os_pretty"; printf ',\n'
    jq_str arch "$arch"; printf ',\n'
    jq_str libc "$libc"; printf '\n  },\n'
    printf '  "init": {\n'
    jq_str system "$init"; printf '\n  },\n'
    printf '  "pkg": {\n'
    jq_str managers "$pms"; printf ',\n'
    jq_str default "$dpm"; printf ',\n'
    if [ -n "$upgradable" ]; then
        printf '    "upgradable": %s,\n' "$upgradable"
    else
        printf '    "upgradable": null,\n'
    fi
    if [ -n "$security_up" ]; then
        printf '    "securityUpgradable": %s,\n' "$security_up"
    else
        printf '    "securityUpgradable": null,\n'
    fi
    if [ -n "$kernel_pending" ]; then
        # 有内核待升级 → true（这是风险从 R1 提升为 R2 的依据）
        if [ "$kernel_pending" -gt 0 ] 2>/dev/null; then
            printf '    "kernelUpgradePending": true,\n'
        else
            printf '    "kernelUpgradePending": false,\n'
        fi
    else
        printf '    "kernelUpgradePending": null,\n'
    fi
    printf '    "rebootRequired": %s\n  },\n' "$reboot"
    printf '  "virt": {\n'
    jq_str type "$virt"; printf ',\n'
    jq_str container "$container"; printf '\n  },\n'
    printf '  "load": {\n'
    if [ -n "$load1" ]; then printf '    "load1": %s,\n' "$load1"; else printf '    "load1": null,\n'; fi
    if [ -n "$load5" ]; then printf '    "load5": %s,\n' "$load5"; else printf '    "load5": null,\n'; fi
    if [ -n "$load15" ]; then printf '    "load15": %s,\n' "$load15"; else printf '    "load15": null,\n'; fi
    if [ -n "$uptime_v" ]; then printf '    "uptimeSec": %s\n' "$uptime_v"; else printf '    "uptimeSec": null\n'; fi
    printf '  },\n'
    printf '  "hw": {\n'
    # 缺失字段一律 null —— 具体数字为 0 与"未知"必须可区分
    printf '    "cpu": {'
    if [ -n "$cores_v" ]; then printf ' "cores": %s ' "$cores_v"; fi
    printf '},\n'
    printf '    "mem": {'
    if [ -n "$mem_total_mb" ]; then printf ' "totalMb": %s, ' "$mem_total_mb"; fi
    if [ -n "$mem_avail_mb" ]; then printf ' "availMb": %s ' "$mem_avail_mb"; fi
    printf '},\n'
    printf '    "disk": ['
    if [ -n "$disk_size_mb" ]; then
        printf ' { "mount": "/", "sizeMb": %s, "usedPct": %s } ' "$disk_size_mb" "$disk_used_pct"
    fi
    printf ']\n'
    printf '  },\n'
    printf '  "ssh": {\n'
    printf '    "port": %s,\n' "$sport"
    if [ "$pk" = "-" ]; then printf '    "pubkeyAuth": null,\n'; else printf '    "pubkeyAuth": %s,\n' "$pk"; fi
    if [ "$pw" = "-" ]; then printf '    "passwordAuth": null\n'; else printf '    "passwordAuth": %s\n' "$pw"; fi
    printf '  },\n'
    printf '  "caps": {\n'
    printf '    "root": %s,\n' "$root"
    printf '    "sudo": %s,\n' "$sudo_ok"
    if [ "$init" = "systemd" ]; then printf '    "systemd": true,\n'; else printf '    "systemd": false,\n'; fi
    jq_str installDir "$idir"; printf ',\n'
    jq_str installMode "$imode"; printf '\n  }\n'
    printf '}\n'
}

# ---------------------------------------------------------------------------
# 校验（sha256，按可用工具降级）
# ---------------------------------------------------------------------------

sha256_of() {
    if have sha256sum; then
        sha256sum "$1" | awk '{print $1}'
    elif have openssl; then
        openssl dgst -sha256 "$1" | awk '{print $NF}'
    elif have busybox; then
        busybox sha256sum "$1" | awk '{print $1}'
    elif have shasum; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        printf ''
    fi
}

# ---------------------------------------------------------------------------
# 子命令
# ---------------------------------------------------------------------------

cmd_check() {
    emit_facts
}

cmd_selfcheck() {
    set -- $(pick_install_dir)
    printf 'agentVersion=%s\n' "$VMPROBE_AGENT_VERSION"
    printf 'probeVersion=%s\n' "$VMPROBE_PROBE_VERSION"
    printf 'uid=%s\n' "$(id -u 2>/dev/null || printf '?')"
    printf 'installDir=%s\n' "$1"
    printf 'installMode=%s\n' "${2:-none}"
    printf 'systemBinary=%s\n' "$([ -x "$SYS_BIN" ] && printf yes || printf no)"
    printf 'logDir=%s\n' "$([ -d "$LOG_DIR" ] && printf present || printf absent)"
    printf 'sha256Tool=%s\n' "$(have sha256sum && printf sha256sum || (have openssl && printf openssl || printf none))"
}

cmd_install() {
    src="$1"
    want_sha="${2:-}"
    no_verify="${3:-}"

    [ -f "$src" ] || { printf 'vmprobe: 源文件不存在: %s\n' "$src" >&2; exit 2; }

    # 0) **默认强制校验**（fail-closed）。
    #    原实现只在缺 sha256 时打个警告就继续安装 —— 那与本系统其余部分
    #    （动作参数未接线即阻断、审批不可用即拒绝）的 fail-closed 原则自相矛盾：
    #    未经校验的二进制会被直接装到被控机上，这是整条链上最不该放宽的一环。
    #    确实需要跳过时，必须显式写出 --no-verify（留下意图痕迹）。
    if [ -z "$want_sha" ] && [ "$no_verify" != "--no-verify" ]; then
        printf 'vmprobe: 拒绝安装 —— 未提供 --sha256。\n' >&2
        printf '  默认强制校验二进制完整性；如确认要跳过，请显式加 --no-verify。\n' >&2
        exit 8
    fi

    set -- $(pick_install_dir)
    idir="$1"; imode="${2:-none}"
    [ "$imode" = "none" ] && { printf 'vmprobe: 找不到可写目录，安装中止\n' >&2; exit 3; }

    # 1) 校验
    if [ -n "$want_sha" ]; then
        got=$(sha256_of "$src")
        if [ -z "$got" ]; then
            printf 'vmprobe: 无法计算 sha256（缺少 sha256sum/openssl/busybox），拒绝在未校验的情况下安装\n' >&2
            exit 4
        fi
        if [ "$got" != "$want_sha" ]; then
            printf 'vmprobe: sha256 不匹配\n  期望 %s\n  实际 %s\n' "$want_sha" "$got" >&2
            exit 5
        fi
        printf 'vmprobe: sha256 校验通过\n'
    else
        printf 'vmprobe: 警告 —— 已按 --no-verify 跳过完整性校验（不推荐）\n' >&2
    fi

    # 2) 落地（install 优先，退回 cp+chmod）
    mkdir -p "$idir" || { printf 'vmprobe: 无法创建 %s\n' "$idir" >&2; exit 6; }
    dst="$idir/vmprobe"
    if have install; then
        install -m 0755 "$src" "$dst" || exit 7
    else
        cp "$src" "$dst" && chmod 0755 "$dst" || exit 7
    fi

    # 3) 入口软链（仅系统级且可写时）
    if [ "$imode" = "system" ] || [ "$imode" = "system-userwritable" ]; then
        bindir=$(dirname "$SYS_BIN")
        if [ -w "$bindir" ] 2>/dev/null; then
            ln -sf "$dst" "$SYS_BIN" 2>/dev/null && printf 'vmprobe: 已链接 %s\n' "$SYS_BIN"
        fi
    fi

    printf 'vmprobe: 已安装到 %s（模式 %s）\n' "$dst" "$imode"
    [ "$imode" = "volatile" ] && printf 'vmprobe: 注意 —— 安装在 /dev/shm，重启后消失（仅临时降级）\n' >&2
    exit 0
}

cmd_uninstall() {
    purge="${1:-}"
    removed=""

    # 必须覆盖**三种**安装位置，否则用户级/临时安装会变成卸载不掉的残留。
    # （原实现只删系统级路径，用户级安装会留下 ~/.local/lib/vmprobe 与二进制。）
    for d in "$SYS_DIR" "${HOME:-/tmp}/.local/lib/vmprobe" /dev/shm/vmprobe; do
        if [ -d "$d" ]; then
            rm -rf "$d" 2>/dev/null && removed="$removed $d"
        fi
    done
    for b in "$SYS_BIN" "${HOME:-/tmp}/.local/bin/vmprobe"; do
        if [ -e "$b" ] || [ -L "$b" ]; then
            rm -f "$b" 2>/dev/null && removed="$removed $b"
        fi
    done

    if [ -n "$removed" ]; then
        printf 'vmprobe: 已移除：%s\n' "$(printf '%s' "$removed" | sed 's/^ //')"
    else
        printf 'vmprobe: 未发现任何已安装的协从端（可能本来就没装）\n'
    fi

    if [ "$purge" = "--purge" ]; then
        rm -rf "$LOG_DIR" 2>/dev/null || true
        printf 'vmprobe: 已删除日志目录 %s\n' "$LOG_DIR"
    else
        printf 'vmprobe: 日志保留在 %s（如需一并删除：--uninstall --purge）\n' "$LOG_DIR"
    fi
    exit 0
}

# ---------------------------------------------------------------------------

main() {
    action="${1:---check}"
    shift 2>/dev/null || true
    case "$action" in
        --check)      cmd_check ;;
        --selfcheck)  cmd_selfcheck ;;
        --install)
            src="${1:-}"
            [ -n "$src" ] || { printf '用法: bootstrap.sh --install <src> [--sha256 X | --no-verify]\n' >&2; exit 2; }
            shift
            want_sha=""; no_verify=""
            while [ $# -gt 0 ]; do
                case "$1" in
                    --sha256)     want_sha="${2:-}"; shift 2 ;;
                    --no-verify)  no_verify="--no-verify"; shift ;;
                    *)            printf 'vmprobe: 未知选项 %s\n' "$1" >&2; exit 2 ;;
                esac
            done
            cmd_install "$src" "$want_sha" "$no_verify"
            ;;
        --uninstall)  cmd_uninstall "${1:-}" ;;
        -h|--help)
            sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
            ;;
        *)
            printf 'vmprobe: 未知参数 %s（用 --help 查看用法）\n' "$action" >&2
            exit 2
            ;;
    esac
}

main "$@"
