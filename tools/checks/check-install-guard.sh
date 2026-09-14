#!/bin/sh
# 验证 agent/bootstrap.sh --install 的**完整性校验默认策略**（对应 ISSUES.md I12）。
#
# 背景：原实现"未提供 --sha256 时只打个警告就继续安装"，与本系统其余部分的
# fail-closed 原则自相矛盾 —— 未经校验的二进制会被直接装到被控机上。
# 现在默认拒绝，只有显式写出 --no-verify 才跳过。
#
# 用临时 HOME，避免往真实家目录写任何东西。
#
#   sh tools/checks/check-install-guard.sh

set -u

SCRIPT_DIR=$(dirname "$0")
BOOT="$SCRIPT_DIR/../../agent/bootstrap.sh"

TMP=$(mktemp -d 2>/dev/null || printf '/tmp/vmprobe-guard-%s' "$$")
mkdir -p "$TMP/home"
export HOME="$TMP/home"

SRC="$TMP/dummy-bin"
printf '#!/bin/sh\necho vmprobe-agent-stub\n' > "$SRC"
GOOD=$(sha256sum "$SRC" 2>/dev/null | awk '{print $1}')
if [ -z "$GOOD" ]; then
    # 没有 sha256sum 就用 openssl
    GOOD=$(openssl dgst -sha256 "$SRC" 2>/dev/null | awk '{print $NF}')
fi

pass=0
fail=0
check() {
    label="$1"; expect="$2"; actual="$3"
    if [ "$expect" = "$actual" ]; then
        printf '  ✔ %s（exit=%s）\n' "$label" "$actual"
        pass=$((pass + 1))
    else
        printf '  ✖ %s（期望 exit=%s，实际 exit=%s）\n' "$label" "$expect" "$actual"
        fail=$((fail + 1))
    fi
}

echo '安装完整性校验策略（临时 HOME='"$HOME"'）'

# 1) 未提供 sha256 → 必须拒绝（exit 8）
sh "$BOOT" --install "$SRC" >"$TMP/1.out" 2>"$TMP/1.err"
check '无 --sha256 时拒绝安装' '8' "$?"
grep -q '拒绝安装' "$TMP/1.err" && printf '      拒绝理由：%s\n' "$(head -n 1 "$TMP/1.err")" || {
    printf '  ✖ 拒绝理由缺失\n'; fail=$((fail + 1));
}

# 2) sha256 不匹配 → 必须拒绝（exit 5）
sh "$BOOT" --install "$SRC" --sha256 0000000000000000000000000000000000000000000000000000000000000000 >"$TMP/2.out" 2>"$TMP/2.err"
check 'sha256 不匹配时拒绝安装' '5' "$?"

# 3) sha256 正确 → 应成功（exit 0）
if [ -n "$GOOD" ]; then
    sh "$BOOT" --install "$SRC" --sha256 "$GOOD" >"$TMP/3.out" 2>"$TMP/3.err"
    check 'sha256 正确时安装成功' '0' "$?"
    if [ -f "$HOME/.local/lib/vmprobe/vmprobe" ]; then
        printf '  ✔ 二进制确实落地到用户级目录\n'; pass=$((pass + 1))
    else
        printf '  ✖ 二进制未落地\n'; fail=$((fail + 1))
    fi
else
    printf '  ⚠ 本机无法计算 sha256，跳过第 3 项\n'
fi

# 4) 显式 --no-verify → 允许安装，但必须留下警告
sh "$BOOT" --install "$SRC" --no-verify >"$TMP/4.out" 2>"$TMP/4.err"
check '显式 --no-verify 时允许安装' '0' "$?"
if grep -q '跳过完整性校验' "$TMP/4.err"; then
    printf '  ✔ 跳过校验时有明确警告\n'; pass=$((pass + 1))
else
    printf '  ✖ 跳过校验时无警告\n'; fail=$((fail + 1))
fi

# 5) 未知选项 → 拒绝（exit 2）
sh "$BOOT" --install "$SRC" --bogus-flag >"$TMP/5.out" 2>"$TMP/5.err"
check '未知选项被拒绝' '2' "$?"

# 6) 卸载必须清干净（含用户级安装）—— 对应 I13 类问题的回归
sh "$BOOT" --uninstall >"$TMP/6.out" 2>"$TMP/6.err"
if [ -e "$HOME/.local/lib/vmprobe/vmprobe" ]; then
    printf '  ✖ 卸载后用户级二进制仍存在\n'; fail=$((fail + 1))
else
    printf '  ✔ 卸载清掉了用户级安装\n'; pass=$((pass + 1))
fi

rm -rf "$TMP"
echo ''
if [ "$fail" -eq 0 ]; then
    printf '全部通过 ✔（%s 项）\n' "$pass"
    exit 0
fi
printf '失败 %s 项 ✖（通过 %s 项）\n' "$fail" "$pass"
exit 1
