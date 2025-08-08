# SM3 Hash Project (x86-64 AVX2)

包含：
- `sm3_base.c`：**普通版** SM3（标量实现，`sm3_base()` 与流式 `sm3_{init,update,final}`）。
- `sm3_parrele.c`：**4 路并行**，当四条消息长度一致时走 **AVX2 快路径**（向量化轮函数）；长度不一致自动回退到可移植实现。
- `sm3_benchmark.c`：对比 base 与 par4 吞吐率（MB/s）与 cycles/byte。
- `sm3.h`：对外 API 头文件。
- `CMakeLists.txt`：构建脚本，默认尝试启用 AVX2。

## 构建
```bash
mkdir build && cd build
cmake -DENABLE_AVX2=ON ..
cmake --build . -j
```
生成 `sm3_benchmark`。

## 运行
```bash
./sm3_benchmark
```

## 备注
- 该 AVX2 实现采用 **W/W′ 标量展开 + AVX2 打包** 的策略，实现简单、收益明显且易于维护。
- 若要进一步压榨性能（更大增益），可以将 W 扩展和压缩循环完全改写为 **纯 AVX2** 运算，或并行度扩展为 8-way；告诉我你的 CPU 型号与目标消息长度分布，我可继续深度优化。
