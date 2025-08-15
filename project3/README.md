# project3 - MyPoseidon2 零知识证明

## 项目描述
这个项目实现了 MyPoseidon2，一种用于零知识证明和 zk-SNARKs 的库。MyPoseidon2 是一种高效的零知识证明系统，广泛应用于隐私保护、身份验证和区块链等领域。

## 文件结构
- `myposeidon2.circom`: MyPoseidon2 的电路定义文件。
- `input.json`: 用于生成证明的输入数据。
- `groth16.sh`: Groth16 证明生成脚本。
- `circom/`: Circom 编译器和相关工具。
- `myposeidon2_js/`: JavaScript 绑定和工具。
- `poseidon2_circuit/`: Poseidon2 电路实现。

## 项目功能
- **电路定义**: 定义了 MyPoseidon2 的电路结构。
- **证人生成**: 支持通过 `generate_witness.js` 生成零知识证明。
- **证明验证**: 提供验证证明的功能。
- **JavaScript 绑定**: 方便在 Web 应用中使用。

## 依赖
- Node.js 14 或更高版本
- npm 6 或更高版本
- Circom 1.0 或更高版本

## 编译与运行
1. 安装依赖：
   ```bash

   npm install -g circom snarkjs

   mkdir poseidon2_circuit && cd  poseidon2_circuit
   ```
2. 编译：
   ```bash
   circom myposeidon2.circom --r1cs --wasm --sym
   ```
3. 生成证人：
   ```bash
   node myposeidon2_js/generate_witness.js myposeidon2_js/myposeidon2.wasm input.json witness.wtns
   ```
4. 验证证明：
   ```bash
   ./groth16.sh
   ```
