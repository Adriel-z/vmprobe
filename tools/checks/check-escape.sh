#!/bin/sh
# 验证 agent/bootstrap.sh 的 json_escape 能处理**不可信输入**产生的控制字符。
#
# 为什么单独测这一条：facts 的值来自被控机上的文件（os-release、hostname 等）。
# 一台被入侵的虚拟机可以写入含换行/制表符/引号/反斜杠的 PRETTY_NAME，
# 如果转义不到位，主控端解析 facts 时会直接 JSON 解析失败 ——
# 即"被控机可以用一个字符串让控制器的探针失效"。
#
# 用法：sh tools/checks/check-escape.sh   （退出码 0 = 通过）

set -u

# 引入被测函数（脚本末尾的 main 在无参数时会走 --check，不 exit，因此可安全 source）
VMPROBE_SOURCE=1
. "$(dirname "$0")/../../agent/bootstrap.sh" >/dev/null 2>&1 || true

# 恶意/异常值：换行、制表符、引号、反斜杠、退格、DEL
evil=$(printf 'a\nb\tc"d\\e\010f\177g')

escaped=$(json_escape "$evil")

# 拼成 JSON 后必须仍能被严格解析
printf '{"v":"%s"}\n' "$escaped"
