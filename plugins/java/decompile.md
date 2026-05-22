# Java CFR 反编译策略

## 适用场景

当项目包含 `.class` 或 `.jar` 文件且对应 `.java` 源码不存在时，使用 CFR 反编译器提取源码。

## 工具获取

CFR 版本 0.152+，下载地址：https://github.com/leibnitz27/cfr/releases

## 使用方式

### 单文件反编译
```bash
java -jar cfr.jar MyClass.class --outputdir decompiled/
```

### JAR 包反编译
```bash
java -jar cfr.jar myapp.jar --outputdir decompiled/
```

### 批量反编译（目录递归）
```bash
find . -name '*.class' | xargs -L 50 java -jar cfr.jar --outputdir decompiled/
```

**注意**：CFR 不接受目录作为输入，必须用 `find | xargs` 递归处理。

## 反编译策略

### 最小模式（推荐）
仅反编译需要的类，按需扩展：
1. 先反编译 T1 层（Controller/Filter/Servlet）
2. 根据 T1 的调用链，按需反编译 T2 层（Service/DAO）
3. 仅当 T2 调用了 T3 且 T3 无源码时才反编译 T3

### 分层模式
按 Layer 批量反编译：
- Layer 1: Controllers/Actions/Servlets
- Layer 2: Services
- Layer 3: DAOs/Repositories

## 源码优先策略

1. 如果 `.java` 源码存在，优先使用源码
2. 仅对没有对应源码的 `.class` 文件进行反编译
3. 反编译结果缓存到 `{output_path}/decompiled/`，避免重复反编译

## 注意事项

- 混淆代码的变量名可能被重命名为 `var_N`，但注解通常保留
- 泛型信息可能在编译时被擦除
- Lambda 表达式的反编译结果可能不直观
- 反编译代码的行号可能与原始源码不一致，需在报告中注明"反编译"
