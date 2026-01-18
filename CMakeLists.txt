cmake_minimum_required(VERSION 3.10)

# 项目名称
project(GameCore)

# 设置为 C++ 17 标准
set(CMAKE_CXX_STANDARD 17)

# 生成 DLL (SHARED)
add_library(GameCore SHARED GameCore.cpp)

# Windows 下需要链接的系统库 (Kernel32等)
if(WIN32)
    target_link_libraries(GameCore PRIVATE kernel32 user32 gdi32 winspool shell32 ole32 oleaut32 uuid comdlg32 advapi32)
endif()
