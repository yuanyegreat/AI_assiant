cmake_minimum_required(VERSION 3.10)

# 项目名称 (可以保持 GameCore 或者改成 NightreignGameCore，影响不大)
project(NightreignGameCore)

# 设置为 C++ 17 标准
set(CMAKE_CXX_STANDARD 17)

# ⚠️ 关键修改在这里：
# add_library(最终生成的DLL名字 SHARED 你的源代码文件名.cpp)
# 这里把原来的 GameCore.cpp 改成了 NightreignGameCore.cpp
add_library(NightreignGameCore SHARED NightreignGameCore.cpp)

# Windows 下需要链接的系统库 (Kernel32等)
if(WIN32)
    # 注意：这里的第一个参数必须和上面的 add_library 里的名字一致 (即 NightreignGameCore)
    target_link_libraries(NightreignGameCore PRIVATE kernel32 user32 gdi32 winspool shell32 ole32 oleaut32 uuid comdlg32 advapi32)
endif()
