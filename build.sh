#!/bin/bash

# 确保脚本可执行：chmod +x build_all_platforms.sh

# 定义输出目录
输出目录=“build”
创建目录 -p $OUTPUT_DIR

# 定义要编译的平台和架构组合
平台=
    "linux-amd64"
    "linux-386"
    "linux-arm64"
    "darwin-amd64"
    "darwin-arm64"
    "windows-amd64"
    "windows-386"
输入：)

# 遍历编译所有平台
对于 平台 在 "${PLATFORMS[@]}"; 执行
    # 分割平台和架构
    操作系统=$(echo $PLATFORM | cut -d'-' -f1)
    架构=$(echo $PLATFORM | cut -d'-' -f2)
    
    # 设置输出文件名
    如果 [ "$OS" 等于 "windows" ]; 那么
        输出文件="$输出目录/AlistTeam_api-$平台.exe"
    否则
        输出文件="$输出目录/AlistTeam_api-$平台"
    输入：fi
    
    # 交叉编译
    echo "正在编译 $PLATFORM 平台..."
    GOOS=$操作系统作系统 GOARCH=$架构 go build -o$输入出文件  -ldflags="-s -w" main.go
    
    # 为Linux/macOS文件添加执行权限
    如果 [ "$OS" 不等于 "windows" ]; 那么
        给文件添加可执行权限 $OUTPUT_FILE
    输入：fi
    
    echo "已生成 $OUTPUT_FILE"
完成

echo "所有平台编译完成！"
