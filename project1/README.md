# project1 - SM4 实现

## 项目描述
这个项目包含了多种 SM4 块密码算法的实现，包括标准实现、T表优化实现以及 GCM 模式实现。目标是提供高效且优化的 SM4 算法实现，适用于各种应用场景。

## 文件结构
- `sm4.c` 和 `sm4.h`: 标准 SM4 实现的源文件和头文件。
- `sm4_withTtable.c`: 使用 T 表优化的 SM4 实现，提高了性能。
- `sm4_gcm.c`: SM4 的 GCM 模式实现，提供更高的安全性。
- `main.c`: 演示和测试 SM4 实现的主程序。
- `T-tablegen.c`: 生成 T 表的工具。
- `CMakeLists.txt`: CMake 构建配置文件。
- `build/`: 构建生成目录，包含编译结果如 `libsm4.a`、`libsm4ttable.a` 和 `sm4_demo`。

## 编译与运行
1. 创建构建目录并运行 CMake：
   ```bash
   mkdir build
   cd build
   cmake ..
   make
   ```
2. 执行生成的二进制文件：
   ```bash
   ./sm4_demo
   ```
3.gcm版本中带有AESNi等优化，故需要跑在Intel Xeon的硬件核心上，i7无法支持。
```
   With AVX-512 rotate-left intrinsics (for L transform speedup in parallel path):
     cc -O3 -Wall -Wextra -mavx512f -mavx512vl -DSM4_USE_AVX512 -o sm4_gcm sm4_gcm.c
     cc -O3 -Wall -Wextra -mavx512f -mavx512vl -DSM4_USE_AVX512 -o sm4_gcm sm4_gcm.c

  self-test:
   ./sm4_gcm --selftest./
   (checks known-answer test for SM4 block, and a small GCM roundtrip)
```


## 功能
- **标准 SM4 实现**: 提供基本的加密和解密功能。
- **T 表优化**: 通过预计算 T 表提升加密速度。
- **GCM 模式**: 支持更高的安全性和数据完整性。
- **测试程序**: 验证实现的正确性。

## 测试
运行 `sm4_demo` 可执行基本加密和解密测试，确保实现的正确性。

## 依赖
- CMake 3.30.3 或更高版本
- GCC 7.5 或更高版本 / Clang 9.0 或更高版本

## 致谢
- 实现基于 SM4 官方标准，加入了 T 表优化以提升性能。
