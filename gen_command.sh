#!/bin/bash
# 保存为 gen_commands.sh
# 运行：bash gen_commands.sh
# 输出：当前目录下 commands.txt

infile="LinuxOrder.txt"
outfile="commands.txt"
base="/mnt/dataset2/linux"
client="./ShieldReduceClient"

> "$outfile"   # 清空旧文件
while IFS= read -r name; do
    name="${name%"${name##*[![:space:]]}"}"  # 去右端空格
    [[ -z "$name" ]] && continue
    echo "$client -t o -i $base/$name" >> "$outfile"
done < "$infile"

echo "已生成 $outfile ，共 $(wc -l < "$outfile") 条命令。"