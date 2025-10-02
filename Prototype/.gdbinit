# 启用 SGX enclave 内存测量工具 (EMMT)
enable sgx_emmt

# 设置一个标记，用于判断程序是否正常执行完毕
set $_exitcode = -999

# 定义一个 hook，在 GDB 停止时（例如程序结束）触发
define hook-stop
  # 如果程序是正常结束（而不是被断点中断），则自动退出 GDB
  if $_exitcode != -999
    quit
  end
end
