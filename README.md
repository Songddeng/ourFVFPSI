# FV-FPSI

FV-FPSI 是一个面向模糊隐私集合求交（Fuzzy Private Set Intersection, FPSI）的实验原型实现。

本项目实现了基于粗到细候选过滤思想的 FPSI 协议，并支持基于 Binary Fuse Filter（BFF）的候选预过滤机制，用于在精确匹配前缩减候选集合规模，从而降低后续密码学操作的计算与通信开销。

## 1. 编译

首先获取并编译依赖：

```bash
./build.sh
```

`build.sh` 当前主要完成：

* 编译 `secure-join` 至 `thirdparty/out/install`
* 编译 `volePSI` 至 `thirdparty/out/install`
* 获取 `FastFilter/xor_singleheader` 至 `thirdparty/xor_singleheader-master`

随后配置并编译项目：

```bash
cmake -S . -B build
cmake --build build -j
```

编译完成后，主程序位于：

```bash
./build/fpsi
```

## 2. 运行示例

一个典型的运行命令如下：

```bash
./build/fpsi \
  -nn 8 \
  -d 8 \
  -delta 16 \
  -p 2 \
  -prefilter bfuse \
  -reveal_mode 1 \
  -try 1
```

其中：

* `-nn`：集合规模参数，例如 `-nn 8` 表示集合规模为 `2^8 = 256`
* `-d`：数据维度
* `-delta`：模糊匹配距离阈值
* `-p`：距离参数，例如 `-p 2` 表示使用 `L2` 距离
* `-prefilter bfuse`：启用 Binary Fuse Filter 候选过滤
* `-reveal_mode`：结果输出模式
* `-try`：实验运行次数



## 3. 输出示例

程序运行成功后会输出协议统计信息，例如：

```text
[ours]       L2       8    16    256    7.435      0.570      4.670      2.687      0.077

[id-stats] fpsiFilterLp
  Intersection_Context: True_Intersection_Estimate = 8
  Filter_Execution_Result: R_Total_Hits = 8 | R_Blocked_Useless = 248
```

主要统计信息格式为：

```text
[Protocol] [Metric] [Dim] [Delta] [SetSize] [Comm(MB)] [Time(s)] [FMapComm(MB)] [FilterComm(MB)] [OTComm(MB)]
```

其中主要包含：

* 协议名称
* 距离类型
* 数据维度
* 距离阈值
* 集合规模
* 总通信开销
* 总运行时间
* FMap 阶段通信开销
* 候选过滤阶段通信开销
* OT 相关通信开销


## 4. 对比方案

本项目实验参考了以下 FPSI 开源实现。

### Gao et al.

代码：

https://github.com/ql70ql70/Fuzzy-Private-Set-Intersection-from-Fuzzy-Mapping

论文：

https://eprint.iacr.org/2024/1462


### Dang et al.

代码：

https://github.com/zhouxv/ourFuzzyPSI-C

论文：

https://eprint.iacr.org/2025/1796


### Yang et al.

代码：

https://github.com/Th0masAndy/FPSI

该实现作为本文实验中的主要对比方案之一。

## 5. 第三方依赖

本项目使用或依赖以下开源组件：

* `secure-join`
* `volePSI`
* `FastFilter/xor_singleheader`

具体实现及许可证请参考对应项目仓库。

## 6. 致谢

本项目部分实现，主体代码参考或改编自以下开源项目：

* https://github.com/zhouxv/ourFuzzyPSI-C
* https://github.com/Th0masAndy/FPSI

感谢相关作者公开代码并推动 FPSI 研究的可复现性。
