# DDH-based Private Intersection-Sum Protocol

## 1. 协议背景与数学假设

本协议用于在半诚实安全模型下，计算两个参与方数据集合的**交集求和**，即在保护隐私的前提下，求交集元素的权重和。  
该协议基于**判定 Diffie–Hellman 假设（DDH assumption）**，并使用**加法同态加密**（如 Paillier）来实现加权求和。

- **群选择**：选取素数阶 $q$ 的循环群 $G$，生成元为 $g$。  
- **哈希函数**：$H: U \to G$ 将标识符空间 $U$ 中的元素映射到 $G$ 中的随机群元素（可视为 Hash-to-Group）。  
- **安全假设**：
  - **DDH 假设**：对于随机选取的 $a,b \in \mathbb{Z}_q$，$(g, g^a, g^b, g^{ab})$ 与 $(g, g^a, g^b, g^c)$ 在多项式时间内不可区分。  
  - **半诚实模型**：双方按协议执行，但可能试图从中获取额外信息。

---

## 2. 输入与输出

- **P1 输入**：
  $$
  V = \{v_i\}_{i=1}^{m_1},\quad v_i \in U
  $$
- **P2 输入**：
  $$
  W = \{(w_j, t_j)\}_{j=1}^{m_2},\quad w_j \in U,\, t_j \in \mathbb{Z}^+
  $$

- **输出**：
  - P1：无额外交集内容  
  - P2：$S_J = \sum_{j \in J} t_j$，其中 $J$ 为交集索引集。

---

## 3. 协议流程

### Setup 阶段
1. P1 随机选 $k_1 \in \mathbb{Z}_q^*$。  
2. P2 随机选 $k_2 \in \mathbb{Z}_q^*$，并生成加法同态加密 $(pk, sk) \leftarrow \mathsf{AGen}(\lambda)$，将 $pk$ 发给 P1。

---

### Round 1 （P1 → P2）
1. P1 对每个 $v_i$：
   $$
   x_i = H(v_i)^{k_1}
   $$
2. 发送 $\{x_i\}$（打乱顺序）给 P2。

---

### Round 2 （P2 → P1）
1. 对收到的每个 $x_i$：
   $$
   z_i = (x_i)^{k_2} = H(v_i)^{k_1 k_2}
   $$
   得到 $Z = \{z_i\}$。
2. 对每个 $(w_j, t_j)$：
   $$
   y_j = H(w_j)^{k_2}, \quad c_j = \mathsf{AEnc}_{pk}(t_j)
   $$
3. 将 $Z$ 和 $\{(y_j, c_j)\}$（均打乱顺序）发送给 P1。

---

### Round 3 （P1 → P2）
1. 对每个 $(y_j, c_j)$：
   $$
   y'_j = (y_j)^{k_1} = H(w_j)^{k_1 k_2}
   $$
2. 求交集索引集：
   $$
   J = \{ j \mid y'_j \in Z \}
   $$
3. 同态加和：
   $$
   C = \mathsf{ASum}(\{c_j\}_{j \in J}) = \mathsf{AEnc}_{pk}\left( \sum_{j \in J} t_j \right)
   $$
4. 随机化：
   $$
   C' = \mathsf{ARefresh}(C)
   $$
5. 将 $C'$ 发给 P2。

---

### 输出阶段（P2）
P2 解密：
$$
S_J = \mathsf{ADec}_{sk}(C')
$$

---

## 4. 原理推导

- P1 和 P2 分别持有 $k_1$、$k_2$，因此只有双方配合才能得到 $H(x)^{k_1 k_2}$。
- 因为 $H$ 为随机预言机，$H(v_i)^{k_1}$ 与 $H(w_j)^{k_2}$ 在不知道另一方密钥时无法匹配原值，确保非交集元素信息隐藏。
- 同态加密保证了交集权重可加和，但明文不可见。

---

## 5. 正确性证明

若 $v_i = w_j$，则：
$$
(x_i)^{k_2} = (H(v_i)^{k_1})^{k_2} = H(v_i)^{k_1 k_2} = (H(w_j)^{k_2})^{k_1} = y'_j
$$
因此 $y'_j \in Z$ 当且仅当 $v_i = w_j$。

---