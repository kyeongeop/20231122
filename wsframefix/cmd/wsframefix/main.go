// wsframefix: WebSocket 帧长度检查局部修正工具。
package main

import (
	"os"

	"wsframefix/internal/tool"
)

func main() {
	os.Exit(tool.Main(os.Args[1:]))
}
