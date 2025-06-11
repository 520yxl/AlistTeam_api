#!/bin/bash

# 确保脚本可执行：chmod +x build_all_platforms.sh

# 定义输出目录
OUTPUT_DIR="binaries"
mkdir -p $OUTPUT_DIR

# 定义要编译的平台和架构组合
PLATFORMS=(
    "linux-amd64"
    "linux-386"
    "linux-arm64"
    "darwin-amd64"
    "darwin-arm64"
    "windows-amd64"
    "windows-386"
)

# 遍历编译所有平台
for PLATFORM in "${PLATFORMS[@]}"; do
    # 分割平台和架构
    OS=$(echo $PLATFORM | cut -d'-' -f1)
    ARCH=$(echo $PLATFORM | cut -d'-' -f2)
    
    # 设置输出文件名
    if [ "$OS" == "windows" ]; then
        OUTPUT_FILE="$OUTPUT_DIR/alidrive-auth-$PLATFORM.exe"
    else
        OUTPUT_FILE="$OUTPUT_DIR/alidrive-auth-$PLATFORM"
    fi
    
    # 交叉编译
    echo "正在编译 $PLATFORM 平台..."
    GOOS=$OS GOARCH=$ARCH go build -o $OUTPUT_FILE -ldflags="-s -w" main.go
    
    # 为Linux/macOS文件添加执行权限
    if [ "$OS" != "windows" ]; then
        chmod +x $OUTPUT_FILE
    fi
    
    echo "已生成 $OUTPUT_FILE"
done

echo "所有平台编译完成！"