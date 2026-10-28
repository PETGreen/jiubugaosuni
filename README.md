# 密匣 (MiXia)

极简、离线、开源的密码生成与管理器。一套 Flutter 代码同时编译 **Windows EXE** 和 **Android APK**(兼容鸿蒙 4.x 及以下)。

## 特性

- **数据与程序分离**:所有密码加密存储在独立的 `vault.pwm` 文件中,增删改自动加密写回,永不产生明文
- **强加密**:PBKDF2-SHA256(25 万次迭代)派生密钥 + AES-GCM-256 加密,随机盐与随机 nonce
- **生物识别解锁**:指纹 / 人脸(Android)、Windows Hello(Windows),主密码由系统安全区保管
- **密码生成器**:可指定长度、大小写、纯数字/含字母、是否含符号、排除易混淆字符
- **安全检查**:弱密码、重复密码检测与熵评估
- **两端同步**:
  - 手机 ↔ 电脑:加密二维码多帧互扫(数据全程密文)
  - 文件导出/导入(微信、U盘等任意渠道传输的都是密文)
  - 墓碑合并算法,两端离线修改后同步不冲突,删除不复活
- **主题**:浅色 / 深色 / 跟随系统 / 自动昼夜切换(7:00–19:00 浅色)
- **剪贴板保护**:复制内容 30 秒后自动清空

## 安全设计

| 项目 | 说明 |
|---|---|
| 主密码 | 仅存在内存,锁定即清除;开启生物识别后由系统安全区(Android KeyStore / Windows DPAPI)保管 |
| 数据文件 | `vault.pwm` 全程 AES-GCM-256 密文 |
| 传输 | 二维码与导出文件均为密文,被截获也无法破解 |
| 网络 | 应用无任何网络请求,完全离线 |

加密 payload 格式与 WebCrypto 兼容(PBKDF2-SHA256 → AES-GCM),JSON 结构:
`{v:1, kdf, iterations, salt, iv, data}`,`data = cipherText + mac`。

## 编译

```bash
flutter pub get
flutter build windows --release   # Windows 版: build\windows\x64\runner\Release\
flutter build apk --release       # 手机版: build\app\outputs\flutter-apk\app-release.apk
```

> Windows 编译需要 Visual Studio Build Tools(含 C++ ATL/MFC 组件,生物识别安全存储插件依赖)。

## 许可

MIT License,详见 [LICENSE](LICENSE)。
