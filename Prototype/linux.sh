#!/bin/bash

cd /home/helix/repos/shieldreduce/Prototype/bin

DATASET_DIR="/home/helix/repos/linux-test"  # 可自定义数据集路径

# 提示用户输入上传数量
read -p "请输入要上传的文件数量: " MAX_UPLOADS

# 验证输入是否为正整数
if ! [[ "$MAX_UPLOADS" =~ ^[1-9][0-9]*$ ]]; then
    echo "错误: 请输入一个正整数"
    exit 1
fi

echo "将上传 $MAX_UPLOADS 个文件"

count=0

for file in "$DATASET_DIR"/*.tar; do
    if [ -f "$file" ]; then
        echo "Uploading $file ($((count+1))/$MAX_UPLOADS)"
        ./ShieldReduceClient -t o -i "$file"
        count=$((count+1))
        if [ "$count" -ge "$MAX_UPLOADS" ]; then
            echo "已上传 $MAX_UPLOADS 个备份，任务结束。"
            break
        fi
    fi
done

if [ "$count" -eq 0 ]; then
    echo "在目录 $DATASET_DIR 中没有找到 .tar 文件"
elif [ "$count" -lt "$MAX_UPLOADS" ]; then
    echo "只找到 $count 个文件，全部已上传完成。"
fi
