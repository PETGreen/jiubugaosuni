import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:local_auth/local_auth.dart';
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';
import 'package:qr_flutter/qr_flutter.dart';
import 'package:share_plus/share_plus.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:zxing2/qrcode.dart' as zq;
import 'package:image/image.dart' as img;
import 'dart:ui' as ui;

/* ==================== 数据模型 ==================== */

class Entry {
  String id, site, username, password, notes, createdAt, updatedAt;
  Entry({required this.id, required this.site, required this.username,
      required this.password, this.notes = '', required this.createdAt, required this.updatedAt});
  factory Entry.fromJson(Map<String, dynamic> j) => Entry(
        id: j['id'] ?? '', site: j['site'] ?? '', username: j['username'] ?? '',
        password: j['password'] ?? '', notes: j['notes'] ?? '',
        createdAt: j['createdAt'] ?? '', updatedAt: j['updatedAt'] ?? '');
  Map<String, dynamic> toJson() => {
        'id': id, 'site': site, 'username': username, 'password': password,
        'notes': notes, 'createdAt': createdAt, 'updatedAt': updatedAt};
}

class Tombstone {
  String id, deletedAt;
  Tombstone(this.id, this.deletedAt);
  factory Tombstone.fromJson(Map<String, dynamic> j) => Tombstone(j['id'] ?? '', j['deletedAt'] ?? '');
  Map<String, dynamic> toJson() => {'id': id, 'deletedAt': deletedAt};
}

class Vault {
  List<Entry> entries;
  List<Tombstone> tombstones;
  Vault({List<Entry>? entries, List<Tombstone>? tombstones})
      : entries = entries ?? [], tombstones = tombstones ?? [];
  factory Vault.fromJson(Map<String, dynamic> j) => Vault(
        entries: ((j['entries'] as List?) ?? []).map((e) => Entry.fromJson(e)).toList(),
        tombstones: ((j['tombstones'] as List?) ?? []).map((t) => Tombstone.fromJson(t)).toList());
  Map<String, dynamic> toJson() => {
        'entries': entries.map((e) => e.toJson()).toList(),
        'tombstones': tombstones.map((t) => t.toJson()).toList()};
}

/* ==================== 加密(PBKDF2-SHA256 25万次 + AES-GCM 256,与网页版格式兼容) ==================== */

class CryptoService {
  static const int iterations = 250000;

  static Future<SecretKey> deriveKey(String password, List<int> salt, [int? iter]) {
    final pbkdf2 = Pbkdf2(macAlgorithm: Hmac.sha256(), iterations: iter ?? iterations, bits: 256);
    return pbkdf2.deriveKey(secretKey: SecretKey(utf8.encode(password)), nonce: salt);
  }

  static String buildPayload(SecretBox box, String saltB64) => jsonEncode({
        'v': 1, 'kdf': 'PBKDF2-SHA256', 'iterations': iterations,
        'salt': saltB64,
        'iv': base64Encode(box.nonce),
        // WebCrypto 的 AES-GCM 输出是 密文+校验标签 拼接,这里保持一致
        'data': base64Encode(Uint8List.fromList([...box.cipherText, ...box.mac.bytes])),
      });

  static Future<String> encryptVault(SecretKey key, String saltB64, Vault vault) async {
    final aes = AesGcm.with256bits();
    final box = await aes.encrypt(utf8.encode(jsonEncode(vault.toJson())), secretKey: key);
    return buildPayload(box, saltB64);
  }

  static Future<Vault> decryptPayload(SecretKey key, Map<String, dynamic> payload) async {
    final raw = base64Decode(payload['data'] as String);
    final box = SecretBox(raw.sublist(0, raw.length - 16),
        nonce: base64Decode(payload['iv'] as String), mac: Mac(raw.sublist(raw.length - 16)));
    final plain = await AesGcm.with256bits().decrypt(box, secretKey: key);
    return Vault.fromJson(jsonDecode(utf8.decode(plain)));
  }
}

/* ==================== 保险库存储(数据与程序分离:独立的 vault.pwm 文件) ==================== */

class VaultStore {
  SecretKey? key;
  String? saltB64;
  Vault vault = Vault();
  File? file;
  bool get unlocked => key != null;

  /// 数据变更通知,UI 监听它自动刷新
  final revision = ValueNotifier<int>(0);

  /// 主密码仅存内存,锁定即清除;用于"同密码不同盐"的数据包免提示导入
  String? sessionPw;

  static final VaultStore instance = VaultStore();

  Future<File> defaultFile() async {
    final dir = await getApplicationDocumentsDirectory();
    final d = Directory(p.join(dir.path, 'PWM'));
    if (!await d.exists()) await d.create(recursive: true);
    return File(p.join(d.path, 'vault.pwm'));
  }

  Future<bool> dataFileExists() async {
    file ??= await defaultFile();
    return file!.exists();
  }

  Future<void> setup(String password) async {
    final rnd = Random.secure();
    final salt = List<int>.generate(16, (_) => rnd.nextInt(256));
    saltB64 = base64Encode(salt);
    key = await CryptoService.deriveKey(password, salt);
    sessionPw = password;
    vault = Vault();
    file = await defaultFile();
    await save();
  }

  /// 返回 null 表示成功,否则是错误信息
  Future<String?> unlock(String password) async {
    file ??= await defaultFile();
    try {
      final payload = jsonDecode(await file!.readAsString()) as Map<String, dynamic>;
      final k = await CryptoService.deriveKey(
          password, base64Decode(payload['salt'] as String), payload['iterations'] as int?);
      final v = await CryptoService.decryptPayload(k, payload);
      key = k;
      saltB64 = payload['salt'] as String;
      vault = v;
      sessionPw = password;
      revision.value++;
      return null;
    } catch (e) {
      return '主密码错误或数据文件损坏';
    }
  }

  Future<void> save() async {
    final payload = await CryptoService.encryptVault(key!, saltB64!, vault);
    await file!.writeAsString(payload);
    revision.value++;
  }

  Future<void> changePassword(String newPassword) async {
    final rnd = Random.secure();
    final salt = List<int>.generate(16, (_) => rnd.nextInt(256));
    saltB64 = base64Encode(salt);
    key = await CryptoService.deriveKey(newPassword, salt);
    sessionPw = newPassword;
    await save();
  }

  void lock() {
    key = null;
    sessionPw = null;
    vault = Vault();
  }
}

/* ==================== 密码生成 ==================== */

const kCharsets = {
  'upper': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  'lower': 'abcdefghijklmnopqrstuvwxyz',
  'digits': '0123456789',
  'symbols': '!@#\$%^&*()-_=+[]{};:,.<>?/~',
};
const kAmbiguous = 'l1IO0';

class GenOptions {
  int length = 16;
  bool upper = true, lower = true, digits = true, symbols = true, noAmbiguous = false;
  GenOptions copy() => GenOptions()
    ..length = length .. upper = upper .. lower = lower
    .. digits = digits .. symbols = symbols .. noAmbiguous = noAmbiguous;
}

int _randIndex(Random rnd, int max) {
  final limit = (0x100000000 ~/ max) * max;
  int v;
  do { v = rnd.nextInt(0x100000000); } while (v >= limit);
  return v % max;
}

String generatePassword(GenOptions o) {
  var groups = <String>[
    if (o.upper) kCharsets['upper']!,
    if (o.lower) kCharsets['lower']!,
    if (o.digits) kCharsets['digits']!,
    if (o.symbols) kCharsets['symbols']!,
  ];
  if (o.noAmbiguous) {
    groups = groups
        .map((g) => g.split('').where((c) => !kAmbiguous.contains(c)).join())
        .where((g) => g.isNotEmpty).toList();
  }
  final all = groups.join();
  if (all.isEmpty) throw Exception('请至少选择一种字符类型');
  final rnd = Random.secure();
  final chars = <String>[];
  for (final g in groups) { chars.add(g[_randIndex(rnd, g.length)]); }
  while (chars.length < o.length) { chars.add(all[_randIndex(rnd, all.length)]); }
  for (var i = chars.length - 1; i > 0; i--) {
    final j = _randIndex(rnd, i + 1);
    final t = chars[i]; chars[i] = chars[j]; chars[j] = t;
  }
  return chars.take(o.length).join();
}

/* ==================== 强度评估 ==================== */

const kCommonPasswords = {
  '123456','password','123456789','12345678','12345','1234567','qwerty','abc123',
  '111111','123123','admin','letmein','welcome','iloveyou','666666','888888',
  '000000','123321','654321','qwerty123','1q2w3e4r','aa123456','abc123456'
};

class Strength {
  final int score, entropy;
  final String label;
  final Color color;
  final List<String> reasons;
  Strength(this.score, this.label, this.color, this.entropy, this.reasons);
}

Strength strengthOf(String pw) {
  const labels = ['极弱', '弱', '中等', '强', '很强'];
  final colors = [Colors.redAccent, Colors.redAccent, Colors.amber, Colors.green, Colors.green];
  if (pw.isEmpty) return Strength(0, '空', colors[0], 0, ['密码为空']);
  final reasons = <String>[];
  final isCommon = kCommonPasswords.contains(pw.toLowerCase());
  if (isCommon) reasons.add('这是常见弱密码');
  if (pw.length < 8) { reasons.add('长度不足 8 位'); }
  else if (pw.length < 12) { reasons.add('建议至少 12 位'); }
  final hasLower = pw.contains(RegExp(r'[a-z]')), hasUpper = pw.contains(RegExp(r'[A-Z]'));
  final hasDigit = pw.contains(RegExp(r'[0-9]')), hasSymbol = pw.contains(RegExp(r'[^a-zA-Z0-9]'));
  if (!(hasLower && hasUpper)) reasons.add('建议混合大小写字母');
  if (!hasDigit) reasons.add('缺少数字');
  if (!hasSymbol) reasons.add('缺少符号');
  var pool = 0;
  if (hasLower) pool += 26;
  if (hasUpper) pool += 26;
  if (hasDigit) pool += 10;
  if (hasSymbol) pool += 33;
  final entropy = pool == 0 ? 0 : (pw.length * (log(pool) / ln2)).round();
  int score;
  if (isCommon) { score = 0; }
  else if (entropy < 40) { score = 1; }
  else if (entropy < 60) { score = 2; }
  else if (entropy < 80) { score = 3; }
  else { score = 4; }
  return Strength(score, labels[score], colors[score], entropy, reasons);
}

/* ==================== 同步(加密文件 + 二维码多帧,与网页版同协议) ==================== */

const kQrChunk = 600;
final kQrFrameRe = RegExp(r'^PWM1\|(\d+)\|(\d+)\|([\s\S]*)$');

String extractPayloadText(String text) {
  final m = RegExp(r'<script id="vault-data"[^>]*>([\s\S]*?)</script>').firstMatch(text);
  return m != null ? m.group(1)!.trim() : text.trim();
}

class QrCollector {
  int total = 0;
  List<String?> chunks = [];
  void reset() { total = 0; chunks = []; }
  /// 返回 (完成?, 完整数据, 已收/总帧)
  (bool, String, String) feed(String text) {
    final m = kQrFrameRe.firstMatch(text);
    if (m != null) {
      final idx = int.parse(m.group(1)!), tot = int.parse(m.group(2)!);
      if (tot < 1 || tot > 99 || idx < 1 || idx > tot) return (false, '', '无法识别的二维码');
      if (total != tot) { total = tot; chunks = List.filled(tot, null); }
      chunks[idx - 1] ??= m.group(3)!;
      final got = chunks.where((c) => c != null).length;
      if (got == total) return (true, chunks.join(), '$got/$total');
      return (false, '', '已接收 $got/$total 帧,请继续');
    }
    if (text.trim().startsWith('{')) return (true, text, '1/1');
    return (false, '', '二维码内容不是本应用的数据');
  }
}

Future<String> buildSyncPayload() =>
    CryptoService.encryptVault(VaultStore.instance.key!, VaultStore.instance.saltB64!, VaultStore.instance.vault);

List<String> buildQrFrames(String payload) {
  if (payload.length <= kQrChunk) return [payload];
  final n = (payload.length + kQrChunk - 1) ~/ kQrChunk;
  return List.generate(n, (i) => 'PWM1|${i + 1}|$n|${payload.substring(i * kQrChunk, min((i + 1) * kQrChunk, payload.length))}');
}

void mergeVault(Vault remote) {
  final local = VaultStore.instance.vault;
  final map = {for (final e in local.entries) e.id: e};
  for (final re in remote.entries) {
    if (re.id.isEmpty) continue;
    final le = map[re.id];
    if (le == null || re.updatedAt.compareTo(le.updatedAt) > 0) map[re.id] = re;
  }
  final tombs = <String, String>{};
  for (final t in [...local.tombstones, ...remote.tombstones]) {
    if (t.id.isEmpty) continue;
    if (!tombs.containsKey(t.id) || t.deletedAt.compareTo(tombs[t.id]!) > 0) tombs[t.id] = t.deletedAt;
  }
  tombs.forEach((id, dAt) {
    final e = map[id];
    if (e != null && e.updatedAt.compareTo(dAt) <= 0) map.remove(id);
  });
  local.entries = map.values.toList();
  local.tombstones = tombs.entries.map((e) => Tombstone(e.key, e.value)).toList();
}

/* ==================== 主题(明暗/跟随系统/按时自动切换) ==================== */

enum AppThemeMode { system, light, dark, auto }

class ThemeController extends ChangeNotifier {
  static final ThemeController instance = ThemeController();
  AppThemeMode mode = AppThemeMode.system;
  Timer? _timer;

  Future<void> load() async {
    final sp = await SharedPreferences.getInstance();
    final i = sp.getInt('themeMode') ?? 0;
    mode = AppThemeMode.values[i.clamp(0, AppThemeMode.values.length - 1)];
    _scheduleAuto();
    notifyListeners();
  }

  Future<void> setMode(AppThemeMode m) async {
    mode = m;
    final sp = await SharedPreferences.getInstance();
    await sp.setInt('themeMode', m.index);
    _scheduleAuto();
    notifyListeners();
  }

  void _scheduleAuto() {
    _timer?.cancel();
    if (mode == AppThemeMode.auto) {
      // 每分钟检查一次,到点自动切换
      _timer = Timer.periodic(const Duration(minutes: 1), (_) => notifyListeners());
    }
  }

  ThemeMode get materialMode {
    switch (mode) {
      case AppThemeMode.system: return ThemeMode.system;
      case AppThemeMode.light: return ThemeMode.light;
      case AppThemeMode.dark: return ThemeMode.dark;
      case AppThemeMode.auto:
        final h = DateTime.now().hour;
        return (h >= 7 && h < 19) ? ThemeMode.light : ThemeMode.dark;
    }
  }

  String labelOf(AppThemeMode m) => const ['跟随系统', '浅色', '深色', '自动昼夜(7:00-19:00 浅色)'][m.index];
}

/* ==================== 生物识别(指纹/人脸/Windows Hello) ==================== */

class BioService {
  static final BioService instance = BioService();
  final _storage = const FlutterSecureStorage();
  final _auth = LocalAuthentication();

  Future<bool> supported() async {
    try {
      return await _auth.canCheckBiometrics || await _auth.isDeviceSupported();
    } catch (_) { return false; }
  }

  Future<bool> get enabled async {
    try { return await _storage.read(key: 'pwm_master') != null; } catch (_) { return false; }
  }

  Future<void> enable(String password) => _storage.write(key: 'pwm_master', value: password);
  Future<void> disable() => _storage.delete(key: 'pwm_master');

  /// 验证身份,成功返回保存的主密码
  Future<String?> authenticate() async {
    try {
      final ok = await _auth.authenticate(
          localizedReason: '验证指纹 / 人脸以解锁保险库',
          options: const AuthenticationOptions(stickyAuth: true));
      if (!ok) return null;
      return await _storage.read(key: 'pwm_master');
    } catch (_) { return null; }
  }
}

/// 复制到剪贴板,30 秒后若仍是该内容则自动清空,降低泄露风险
void copyText(BuildContext context, String label, String text) {
  Clipboard.setData(ClipboardData(text: text));
  toast(context, '$label已复制(30 秒后自动清空剪贴板)');
  Timer(const Duration(seconds: 30), () async {
    try {
      final d = await Clipboard.getData('text/plain');
      if (d?.text == text) await Clipboard.setData(const ClipboardData(text: ''));
    } catch (_) {}
  });
}

/* ==================== 应用入口 ==================== */

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  ThemeController.instance.load();
  runApp(const PwmApp());
}

class PwmApp extends StatelessWidget {
  const PwmApp({super.key});

  ThemeData _theme(Brightness b) {
    final scheme = ColorScheme.fromSeed(
        seedColor: const Color(0xFF4C6FFF), brightness: b);
    return ThemeData(
      useMaterial3: true,
      colorScheme: scheme,
      cardTheme: CardThemeData(
          elevation: 0,
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16))),
      inputDecorationTheme: InputDecorationTheme(
          border: OutlineInputBorder(borderRadius: BorderRadius.circular(12))),
      snackBarTheme: const SnackBarThemeData(behavior: SnackBarBehavior.floating),
    );
  }

  @override
  Widget build(BuildContext context) => AnimatedBuilder(
        animation: ThemeController.instance,
        builder: (_, __) => MaterialApp(
          title: '就不告诉你',
          debugShowCheckedModeBanner: false,
          theme: _theme(Brightness.light),
          darkTheme: _theme(Brightness.dark),
          themeMode: ThemeController.instance.materialMode,
          home: const LockScreen(),
        ),
      );
}

void toast(BuildContext context, String msg) =>
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(msg), duration: const Duration(seconds: 2)));

/* ==================== 解锁 / 初始化 ==================== */

class LockScreen extends StatefulWidget {
  const LockScreen({super.key});
  @override
  State<LockScreen> createState() => _LockScreenState();
}

class _LockScreenState extends State<LockScreen> {
  final _pw = TextEditingController(), _pw2 = TextEditingController();
  bool _setup = false, _busy = false, _bio = false, _bioTried = false;
  String _error = '';

  bool get _isMobile => Platform.isAndroid || Platform.isIOS;

  @override
  void initState() {
    super.initState();
    VaultStore.instance.dataFileExists().then((e) async {
      if (!mounted) return;
      setState(() => _setup = !e);
      if (e && await BioService.instance.enabled) {
        setState(() => _bio = true);
        _bioUnlock(); // 打开即自动弹出指纹/人脸
      }
    });
  }

  Future<void> _submit() async {
    setState(() { _error = ''; _busy = true; });
    try {
      if (_setup) {
        if (_pw.text.length < 8) { setState(() => _error = '主密码至少 8 位'); return; }
        if (_pw.text != _pw2.text) { setState(() => _error = '两次输入不一致'); return; }
        await VaultStore.instance.setup(_pw.text);
      } else {
        final err = await VaultStore.instance.unlock(_pw.text);
        if (err != null) { setState(() => _error = err); return; }
      }
      await _afterUnlock();
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _bioUnlock() async {
    if (_bioTried) return;
    _bioTried = true;
    final pw = await BioService.instance.authenticate();
    _bioTried = false;
    if (pw == null || !mounted) return;
    final err = await VaultStore.instance.unlock(pw);
    if (err != null) { setState(() => _error = err); return; }
    await _afterUnlock(alreadyBio: true);
  }

  /// 解锁成功后:可开启生物识别,然后进入主界面
  Future<void> _afterUnlock({bool alreadyBio = false}) async {
    if (!mounted) return;
    if (!alreadyBio &&
        await BioService.instance.supported() &&
        !await BioService.instance.enabled) {
      final enable = await showDialog<bool>(context: context, builder: (ctx) => AlertDialog(
        title: const Text('启用指纹 / 人脸解锁?'),
        content: const Text('下次打开时验证指纹或人脸即可解锁,无需再输主密码。\n'
            '主密码由系统安全区(KeyStore / Windows Hello)加密保管,本应用不另行保存。'),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('暂不')),
          FilledButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('启用')),
        ]));
      if (enable == true) {
        await BioService.instance.enable(VaultStore.instance.sessionPw!);
        if (mounted) setState(() => _bio = true);
      }
    }
    if (mounted) {
      Navigator.of(context).pushReplacement(MaterialPageRoute(builder: (_) => const HomeScreen()));
    }
  }

  Future<String?> _askImportPassword() {
    final c = TextEditingController();
    return showDialog<String>(context: context, builder: (ctx) => AlertDialog(
      title: const Text('验证数据主密码'),
      content: TextField(controller: c, obscureText: true, autofocus: true,
          onSubmitted: (v) => Navigator.pop(ctx, v),
          decoration: const InputDecoration(labelText: '该数据包的主密码', border: OutlineInputBorder())),
      actions: [
        TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('取消')),
        FilledButton(onPressed: () => Navigator.pop(ctx, c.text), child: const Text('解锁')),
      ]));
  }

  /// 未设置主密码也可导入:校验数据包主密码后直接解锁进入
  Future<void> _importPayloadText(String text) async {
    final payloadText = extractPayloadText(text);
    final payload = jsonDecode(payloadText) as Map<String, dynamic>;
    if (payload['iv'] == null || payload['data'] == null || payload['salt'] == null) {
      throw Exception('不是有效的加密数据');
    }
    final pw = await _askImportPassword();
    if (pw == null || pw.isEmpty) return;
    setState(() => _busy = true);
    try {
      final k = await CryptoService.deriveKey(
          pw, base64Decode(payload['salt'] as String), payload['iterations'] as int?);
      await CryptoService.decryptPayload(k, payload); // 先验证密码正确再落盘
      final file = await VaultStore.instance.defaultFile();
      await file.writeAsString(payloadText);
      final err = await VaultStore.instance.unlock(pw);
      if (err != null) { setState(() => _error = err); return; }
      setState(() => _setup = false);
      await _afterUnlock();
    } catch (_) {
      setState(() => _error = '主密码与数据包不匹配,导入未生效');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _importExisting() async {
    final files = await FilePicker.pickFiles();
    if (files.isEmpty) return;
    final f = files.first;
    final text = f.path != null ? await File(f.path!).readAsString() : utf8.decode(await f.readAsBytes());
    try {
      await _importPayloadText(text);
    } catch (e) {
      setState(() => _error = '导入失败:文件格式不正确');
    }
  }

  Future<void> _importByScan() async {
    final result = await Navigator.of(context).push<String>(
        MaterialPageRoute(builder: (_) => const QrScanPage()));
    if (result == null) return;
    try {
      await _importPayloadText(result);
    } catch (e) {
      setState(() => _error = '导入失败: $e');
    }
  }

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Scaffold(
      body: Container(
        decoration: BoxDecoration(gradient: LinearGradient(
          begin: Alignment.topLeft, end: Alignment.bottomRight,
          colors: [scheme.primaryContainer.withValues(alpha: 0.5), scheme.surface])),
        child: Center(
          child: SingleChildScrollView(
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 400),
              child: Card(
                margin: const EdgeInsets.all(20),
                child: Padding(
                  padding: const EdgeInsets.all(28),
                  child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.stretch, children: [
                    Icon(Icons.lock_outline, size: 44, color: scheme.primary),
                    const SizedBox(height: 10),
                    Text('就不告诉你', textAlign: TextAlign.center,
                        style: Theme.of(context).textTheme.headlineSmall),
                    const SizedBox(height: 4),
                    Text(_setup ? '首次使用,请设置主密码' : '输入主密码解锁',
                        textAlign: TextAlign.center,
                        style: Theme.of(context).textTheme.bodySmall),
                    const SizedBox(height: 18),
                    TextField(
                      controller: _pw, obscureText: true, autofocus: !_bio,
                      decoration: const InputDecoration(labelText: '主密码', prefixIcon: Icon(Icons.key)),
                      onSubmitted: (_) => _submit()),
                    if (_setup) ...[
                      const SizedBox(height: 12),
                      TextField(
                        controller: _pw2, obscureText: true,
                        decoration: const InputDecoration(labelText: '确认主密码', prefixIcon: Icon(Icons.key)),
                        onSubmitted: (_) => _submit()),
                    ],
                    if (_error.isNotEmpty)
                      Padding(padding: const EdgeInsets.only(top: 10),
                          child: Text(_error, style: TextStyle(color: scheme.error))),
                    const SizedBox(height: 18),
                    Row(children: [
                      Expanded(child: FilledButton(
                        onPressed: _busy ? null : _submit,
                        child: Text(_busy ? '处理中…' : (_setup ? '创建保险库' : '解锁')))),
                      if (_bio && !_setup) ...[
                        const SizedBox(width: 10),
                        IconButton.filledTonal(
                          icon: const Icon(Icons.fingerprint), tooltip: '指纹 / 人脸解锁',
                          onPressed: _bioUnlock),
                      ],
                    ]),
                    const SizedBox(height: 10),
                    Wrap(alignment: WrapAlignment.center, children: [
                      TextButton.icon(
                        onPressed: _importExisting,
                        icon: const Icon(Icons.file_open, size: 18),
                        label: const Text('导入数据文件')),
                      if (_isMobile)
                        TextButton.icon(
                          onPressed: _importByScan,
                          icon: const Icon(Icons.qr_code_scanner, size: 18),
                          label: const Text('扫码导入')),
                    ]),
                    const SizedBox(height: 4),
                    Text('数据加密存储在独立的 vault.pwm 文件中,与程序分离;没有主密码任何人无法查看。\n'
                        '尚未设置主密码也可以直接导入加密数据,验证数据包主密码即可使用。',
                        textAlign: TextAlign.center,
                        style: Theme.of(context).textTheme.bodySmall),
                  ]),
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}

/* ==================== 主界面 ==================== */

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});
  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  int _tab = 0;
  String _query = '';
  final _genOptions = GenOptions();

  Future<void> _autoSave() async {
    await VaultStore.instance.save();
    if (mounted) toast(context, '已自动保存到 vault.pwm');
  }

  void _lock() {
    VaultStore.instance.lock();
    Navigator.of(context).pushAndRemoveUntil(
        MaterialPageRoute(builder: (_) => const LockScreen()), (_) => false);
  }

  Future<void> _showThemeDialog() async {
    final tc = ThemeController.instance;
    await showDialog(context: context, builder: (ctx) => SimpleDialog(
      title: const Text('外观'),
      children: [
        RadioGroup<AppThemeMode>(
          groupValue: tc.mode,
          onChanged: (v) { if (v != null) tc.setMode(v); Navigator.pop(ctx); },
          child: Column(children: AppThemeMode.values.map((m) =>
              RadioListTile<AppThemeMode>(value: m, title: Text(tc.labelOf(m)))).toList()),
        ),
      ]));
  }

  Future<void> _toggleBio() async {
    if (await BioService.instance.enabled) {
      await BioService.instance.disable();
      if (mounted) toast(context, '已关闭指纹 / 人脸解锁');
    } else {
      if (!await BioService.instance.supported()) {
        if (mounted) toast(context, '当前设备不支持生物识别');
        return;
      }
      final pw = await BioService.instance.authenticate();
      if (pw == null) return; // 用户取消
      await BioService.instance.enable(VaultStore.instance.sessionPw!);
      if (mounted) toast(context, '已启用指纹 / 人脸解锁');
    }
  }

  Future<void> _openSettings() async {
    final bioOn = await BioService.instance.enabled;
    if (!mounted) return;
    showDialog(context: context, builder: (ctx) => SimpleDialog(
      title: const Text('设置'),
      children: [
        ListTile(leading: const Icon(Icons.palette_outlined), title: const Text('外观'),
            subtitle: Text(ThemeController.instance.labelOf(ThemeController.instance.mode)),
            onTap: () { Navigator.pop(ctx); _showThemeDialog(); }),
        ListTile(leading: const Icon(Icons.fingerprint), title: const Text('指纹 / 人脸解锁'),
            subtitle: Text(bioOn ? '已启用,点按关闭' : '未启用,点按开启'),
            onTap: () { Navigator.pop(ctx); _toggleBio(); }),
        ListTile(leading: const Icon(Icons.password), title: const Text('修改主密码'),
            onTap: () { Navigator.pop(ctx); _changePassword(); }),
        ListTile(leading: const Icon(Icons.lock_outline), title: const Text('立即锁定'),
            onTap: () { Navigator.pop(ctx); _lock(); }),
      ]));
  }

  @override
  Widget build(BuildContext context) {
    final pages = [
      VaultTab(query: _query, onChanged: _autoSave, genOptions: _genOptions),
      GeneratorTab(options: _genOptions, onSaveToVault: (pw) => _openEditor(password: pw)),
      const AuditTab(),
    ];
    return Scaffold(
      appBar: AppBar(title: const Text('就不告诉你'), actions: [
        IconButton(icon: const Icon(Icons.sync), tooltip: '同步', onPressed: () => showDialog(context: context, builder: (_) => const SyncDialog())),
        IconButton(icon: const Icon(Icons.settings_outlined), tooltip: '设置', onPressed: _openSettings),
      ]),
      body: pages[_tab],
      bottomNavigationBar: NavigationBar(
        selectedIndex: _tab,
        onDestinationSelected: (i) => setState(() => _tab = i),
        destinations: const [
          NavigationDestination(icon: Icon(Icons.list_alt), label: '密码库'),
          NavigationDestination(icon: Icon(Icons.autorenew), label: '生成器'),
          NavigationDestination(icon: Icon(Icons.shield_outlined), label: '安全检查'),
        ]),
      floatingActionButton: _tab == 0
          ? FloatingActionButton(onPressed: () => _openEditor(), child: const Icon(Icons.add))
          : null,
    );
  }

  Future<void> _openEditor({Entry? entry, String? password}) async {
    final result = await showDialog<Entry>(
      context: context,
      builder: (_) => EntryEditorDialog(entry: entry, initialPassword: password, genOptions: _genOptions));
    if (result == null) return;
    final v = VaultStore.instance.vault;
    final idx = v.entries.indexWhere((e) => e.id == result.id);
    if (idx >= 0) { v.entries[idx] = result; }
    else { v.entries.add(result); }
    await _autoSave();
    setState(() => _tab = 0);
  }

  Future<void> _changePassword() async {
    final c1 = TextEditingController(), c2 = TextEditingController();
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('修改主密码'),
        content: Column(mainAxisSize: MainAxisSize.min, children: [
          TextField(controller: c1, obscureText: true,
              decoration: const InputDecoration(labelText: '新主密码(至少 8 位)', border: OutlineInputBorder())),
          const SizedBox(height: 12),
          TextField(controller: c2, obscureText: true,
              decoration: const InputDecoration(labelText: '确认新主密码', border: OutlineInputBorder())),
        ]),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('取消')),
          FilledButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('确认修改')),
        ]));
    if (ok != true) return;
    if (c1.text.length < 8) { toast(context, '新主密码至少 8 位'); return; }
    if (c1.text != c2.text) { toast(context, '两次输入不一致'); return; }
    await VaultStore.instance.changePassword(c1.text);
    if (mounted) toast(context, '主密码已修改并保存');
  }
}

/* ==================== 密码库 ==================== */

class VaultTab extends StatefulWidget {
  final String query;
  final Future<void> Function() onChanged;
  final GenOptions genOptions;
  const VaultTab({super.key, required this.query, required this.onChanged, required this.genOptions});
  @override
  State<VaultTab> createState() => VaultTabState();
}

class VaultTabState extends State<VaultTab> {
  String _query = '';
  final _revealed = <String>{};

  @override
  Widget build(BuildContext context) {
    return ValueListenableBuilder<int>(
      valueListenable: VaultStore.instance.revision,
      builder: (context, _, __) {
        final entries = VaultStore.instance.vault.entries.where((e) =>
            _query.isEmpty || e.site.toLowerCase().contains(_query) || e.username.toLowerCase().contains(_query)).toList();
        return Column(children: [
      Padding(
        padding: const EdgeInsets.all(12),
        child: TextField(
          decoration: const InputDecoration(
            hintText: '搜索站点或用户名…', prefixIcon: Icon(Icons.search), border: OutlineInputBorder()),
          onChanged: (v) => setState(() => _query = v.trim().toLowerCase())),
      ),
      Expanded(
        child: entries.isEmpty
            ? Center(child: Text(_query.isEmpty ? '还没有保存任何密码,点右下角 + 添加' : '没有匹配的条目',
                style: Theme.of(context).textTheme.bodySmall))
            : ListView.builder(
                itemCount: entries.length,
                itemBuilder: (ctx, i) => _entryCard(entries[i]))),
        ]);
      },
    );
  }

  Widget _entryCard(Entry e) {
    final shown = _revealed.contains(e.id);
    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 12, vertical: 5),
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text(e.site, style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 16)),
          if (e.username.isNotEmpty)
            Row(children: [
              Expanded(child: Text(e.username, style: Theme.of(context).textTheme.bodySmall)),
              InkWell(
                onTap: () => copyText(context, '账户名', e.username),
                borderRadius: BorderRadius.circular(6),
                child: Padding(padding: const EdgeInsets.all(2),
                    child: Icon(Icons.copy, size: 14,
                        color: Theme.of(context).colorScheme.outline)),
              ),
            ]),
          const SizedBox(height: 8),
          Row(children: [
            Expanded(child: Text(shown ? e.password : '••••••••',
                style: const TextStyle(fontFamily: 'monospace'), overflow: TextOverflow.ellipsis)),
            IconButton(icon: Icon(shown ? Icons.visibility_off : Icons.visibility, size: 20),
                tooltip: shown ? '隐藏' : '显示',
                onPressed: () => setState(() => shown ? _revealed.remove(e.id) : _revealed.add(e.id))),
            IconButton(icon: const Icon(Icons.copy, size: 20), tooltip: '复制密码',
                onPressed: () => copyText(context, '密码', e.password)),
            IconButton(icon: const Icon(Icons.edit, size: 20), tooltip: '编辑', onPressed: () async {
              final result = await showDialog<Entry>(context: context,
                  builder: (_) => EntryEditorDialog(entry: e, genOptions: widget.genOptions));
              if (result != null) {
                final v = VaultStore.instance.vault;
                v.entries[v.entries.indexWhere((x) => x.id == e.id)] = result;
                await widget.onChanged();
                setState(() {});
              }
            }),
            IconButton(icon: const Icon(Icons.delete_outline, size: 20, color: Colors.redAccent),
                tooltip: '删除', onPressed: () => _delete(e)),
          ]),
          if (e.notes.isNotEmpty)
            Text(e.notes, style: Theme.of(context).textTheme.bodySmall),
        ]),
      ),
    );
  }

  Future<void> _delete(Entry e) async {
    final ok = await showDialog<bool>(context: context, builder: (ctx) => AlertDialog(
      title: Text('删除「${e.site}」?'),
      actions: [
        TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('取消')),
        FilledButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('删除')),
      ]));
    if (ok != true) return;
    final v = VaultStore.instance.vault;
    v.entries.removeWhere((x) => x.id == e.id);
    v.tombstones.add(Tombstone(e.id, DateTime.now().toUtc().toIso8601String()));
    await widget.onChanged();
    setState(() {});
  }
}

/* ==================== 条目编辑 ==================== */

class EntryEditorDialog extends StatefulWidget {
  final Entry? entry;
  final String? initialPassword;
  final GenOptions genOptions;
  const EntryEditorDialog({super.key, this.entry, this.initialPassword, required this.genOptions});
  @override
  State<EntryEditorDialog> createState() => _EntryEditorDialogState();
}

class _EntryEditorDialogState extends State<EntryEditorDialog> {
  late final _site = TextEditingController(text: widget.entry?.site ?? '');
  late final _user = TextEditingController(text: widget.entry?.username ?? '');
  late final _pw = TextEditingController(text: widget.entry?.password ?? widget.initialPassword ?? '');
  late final _notes = TextEditingController(text: widget.entry?.notes ?? '');
  late final GenOptions _gen = widget.genOptions.copy();
  bool _showPw = false;
  String _error = '';

  void _generate() {
    try {
      setState(() { _pw.text = generatePassword(_gen); _showPw = true; _error = ''; });
    } catch (e) {
      setState(() => _error = e.toString().replaceFirst('Exception: ', ''));
    }
  }

  @override
  Widget build(BuildContext context) => AlertDialog(
        title: Text(widget.entry == null ? '添加条目' : '编辑条目'),
        content: SingleChildScrollView(
          child: Column(mainAxisSize: MainAxisSize.min, children: [
            TextField(controller: _site, decoration: const InputDecoration(
                labelText: '站点 / 名称', hintText: '例如: github.com', border: OutlineInputBorder())),
            const SizedBox(height: 12),
            TextField(controller: _user, decoration: const InputDecoration(
                labelText: '用户名', border: OutlineInputBorder())),
            const SizedBox(height: 12),
            TextField(controller: _pw, obscureText: !_showPw,
              decoration: InputDecoration(labelText: '密码', border: const OutlineInputBorder(),
                suffixIcon: Row(mainAxisSize: MainAxisSize.min, children: [
                  IconButton(icon: Icon(_showPw ? Icons.visibility_off : Icons.visibility),
                      onPressed: () => setState(() => _showPw = !_showPw)),
                  IconButton(icon: const Icon(Icons.autorenew), tooltip: '生成', onPressed: _generate),
                ]))),
            ExpansionTile(
              title: const Text('生成选项', style: TextStyle(fontSize: 14)),
              tilePadding: EdgeInsets.zero,
              children: [
                Row(children: [
                  const Text('长度'), Expanded(child: Slider(
                    value: _gen.length.toDouble(), min: 4, max: 64, divisions: 60,
                    label: '${_gen.length}',
                    onChanged: (v) => setState(() => _gen.length = v.round()))),
                  Text('${_gen.length}'),
                ]),
                _opt('大写字母 A-Z', _gen.upper, (v) => _gen.upper = v),
                _opt('小写字母 a-z', _gen.lower, (v) => _gen.lower = v),
                _opt('数字 0-9(纯数字请只勾此项)', _gen.digits, (v) => _gen.digits = v),
                _opt('符号', _gen.symbols, (v) => _gen.symbols = v),
                _opt('排除易混淆字符 (l 1 I O 0)', _gen.noAmbiguous, (v) => _gen.noAmbiguous = v),
              ]),
            const SizedBox(height: 4),
            TextField(controller: _notes, maxLines: 2, decoration: const InputDecoration(
                labelText: '备注', border: OutlineInputBorder())),
            if (_error.isNotEmpty)
              Padding(padding: const EdgeInsets.only(top: 8),
                  child: Text(_error, style: const TextStyle(color: Colors.redAccent))),
          ]),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context), child: const Text('取消')),
          FilledButton(onPressed: _save, child: const Text('保存')),
        ]);

  Widget _opt(String label, bool value, void Function(bool) set) => CheckboxListTile(
        dense: true, contentPadding: EdgeInsets.zero, controlAffinity: ListTileControlAffinity.leading,
        title: Text(label, style: const TextStyle(fontSize: 13)),
        value: value, onChanged: (v) => setState(() => set(v ?? false)));

  void _save() {
    if (_site.text.trim().isEmpty) { setState(() => _error = '请填写站点 / 名称'); return; }
    if (_pw.text.isEmpty) { setState(() => _error = '请填写密码'); return; }
    final now = DateTime.now().toUtc().toIso8601String();
    Navigator.pop(context, Entry(
      id: widget.entry?.id ?? _newId(),
      site: _site.text.trim(), username: _user.text.trim(),
      password: _pw.text, notes: _notes.text.trim(),
      createdAt: widget.entry?.createdAt ?? now, updatedAt: now));
  }

  String _newId() {
    final rnd = Random.secure();
    return List.generate(16, (_) => rnd.nextInt(256).toRadixString(16).padLeft(2, '0')).join();
  }
}

/* ==================== 生成器 ==================== */

class GeneratorTab extends StatefulWidget {
  final GenOptions options;
  final void Function(String) onSaveToVault;
  const GeneratorTab({super.key, required this.options, required this.onSaveToVault});
  @override
  State<GeneratorTab> createState() => _GeneratorTabState();
}

class _GeneratorTabState extends State<GeneratorTab> {
  String _output = '';
  Strength? _strength;

  void _generate() {
    try {
      setState(() { _output = generatePassword(widget.options); _strength = strengthOf(_output); });
    } catch (e) {
      toast(context, e.toString().replaceFirst('Exception: ', ''));
    }
  }

  @override
  Widget build(BuildContext context) {
    final o = widget.options;
    return SingleChildScrollView(
      padding: const EdgeInsets.all(16),
      child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        Row(children: [
          Expanded(child: TextField(
            controller: TextEditingController(text: _output),
            readOnly: true,
            style: const TextStyle(fontFamily: 'monospace', fontSize: 16),
            decoration: const InputDecoration(hintText: '点击下方按钮生成', border: OutlineInputBorder()))),
          const SizedBox(width: 8),
          IconButton(icon: const Icon(Icons.copy), tooltip: '复制', onPressed: _output.isEmpty ? null : () {
            copyText(context, '密码', _output);
          }),
        ]),
        if (_strength != null) ...[
          const SizedBox(height: 10),
          LinearProgressIndicator(
            value: max(0.08, _strength!.score * 0.25),
            color: _strength!.color, minHeight: 8, borderRadius: BorderRadius.circular(4)),
          const SizedBox(height: 4),
          Text('强度:${_strength!.label}(约 ${_strength!.entropy} 位熵)',
              style: TextStyle(color: _strength!.color, fontSize: 13)),
        ],
        const SizedBox(height: 16),
        Card(child: Padding(padding: const EdgeInsets.all(12), child: Column(children: [
          Row(children: [
            const Text('长度'), Expanded(child: Slider(
              value: o.length.toDouble(), min: 4, max: 64, divisions: 60,
              label: '${o.length}', onChanged: (v) => setState(() => o.length = v.round()))),
            Text('${o.length}'),
          ]),
          _check('大写字母 A-Z', o.upper, (v) => o.upper = v),
          _check('小写字母 a-z', o.lower, (v) => o.lower = v),
          _check('数字 0-9(纯数字请只勾此项)', o.digits, (v) => o.digits = v),
          _check('符号 !@#\$…', o.symbols, (v) => o.symbols = v),
          _check('排除易混淆字符 (l 1 I O 0)', o.noAmbiguous, (v) => o.noAmbiguous = v),
        ]))),
        const SizedBox(height: 12),
        FilledButton.icon(onPressed: _generate, icon: const Icon(Icons.autorenew), label: const Text('生成密码')),
        const SizedBox(height: 8),
        OutlinedButton.icon(
          onPressed: _output.isEmpty ? null : () => widget.onSaveToVault(_output),
          icon: const Icon(Icons.save_alt), label: const Text('保存到密码库')),
      ]),
    );
  }

  Widget _check(String label, bool value, void Function(bool) set) => CheckboxListTile(
        dense: true, contentPadding: EdgeInsets.zero,
        title: Text(label, style: const TextStyle(fontSize: 14)),
        value: value, onChanged: (v) => setState(() => set(v ?? true)));
}

/* ==================== 安全检查 ==================== */

class AuditTab extends StatelessWidget {
  const AuditTab({super.key});

  @override
  Widget build(BuildContext context) {
    return ValueListenableBuilder<int>(
      valueListenable: VaultStore.instance.revision,
      builder: (context, _, __) => _buildContent(context));
  }

  Widget _buildContent(BuildContext context) {
    final entries = VaultStore.instance.vault.entries;
    final byPw = <String, int>{};
    for (final e in entries) { byPw[e.password] = (byPw[e.password] ?? 0) + 1; }
    var weak = 0, reused = 0;
    final items = <Widget>[];
    for (final e in entries) {
      final st = strengthOf(e.password);
      final problems = <(String, Color)>[];
      if (st.score <= 1) { weak++; problems.add(('密码${st.label}(约 ${st.entropy} 位熵)', Colors.redAccent)); }
      else if (st.score == 2) { problems.add(('强度中等(约 ${st.entropy} 位熵)', Colors.amber)); }
      if ((byPw[e.password] ?? 0) > 1) {
        reused++;
        problems.add(('与其他 ${byPw[e.password]! - 1} 个条目重复使用', Colors.redAccent));
      }
      for (final r in st.reasons) { problems.add((r, Colors.amber)); }
      if (problems.isEmpty) continue;
      items.add(Card(
        margin: const EdgeInsets.symmetric(horizontal: 12, vertical: 5),
        child: Padding(padding: const EdgeInsets.all(12), child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text(e.site, style: const TextStyle(fontWeight: FontWeight.bold)),
          if (e.username.isNotEmpty) Text(e.username, style: Theme.of(context).textTheme.bodySmall),
          const SizedBox(height: 6),
          Wrap(spacing: 6, runSpacing: 6, children: problems.map((p) => Chip(
            label: Text(p.$1, style: TextStyle(fontSize: 12, color: p.$2)),
            side: BorderSide(color: p.$2.withValues(alpha: 0.5)),
            backgroundColor: Colors.transparent, visualDensity: VisualDensity.compact)).toList()),
        ]))));
    }
    return ListView(padding: const EdgeInsets.symmetric(vertical: 12), children: [
      Row(children: [
        _sumCard(context, '${entries.length}', '总条目', null),
        _sumCard(context, '$weak', '弱密码', weak > 0 ? Colors.redAccent : Colors.green),
        _sumCard(context, '$reused', '重复使用', reused > 0 ? Colors.redAccent : Colors.green),
      ]),
      const SizedBox(height: 8),
      if (items.isEmpty)
        const Center(child: Padding(padding: EdgeInsets.all(40), child: Text('未发现安全问题')))
      else
        ...items,
    ]);
  }

  Widget _sumCard(BuildContext context, String num, String label, Color? color) => Expanded(
        child: Card(margin: const EdgeInsets.symmetric(horizontal: 6), child: Padding(
          padding: const EdgeInsets.all(14),
          child: Column(children: [
            Text(num, style: TextStyle(fontSize: 26, fontWeight: FontWeight.bold, color: color)),
            Text(label, style: Theme.of(context).textTheme.bodySmall),
          ]))));
}

/* ==================== 同步对话框 ==================== */

class SyncDialog extends StatefulWidget {
  const SyncDialog({super.key});
  @override
  State<SyncDialog> createState() => _SyncDialogState();
}

class _SyncDialogState extends State<SyncDialog> {
  String _error = '';
  bool _busy = false;

  Future<void> _export() async {
    setState(() { _error = ''; _busy = true; });
    try {
      final payload = await buildSyncPayload();
      final d = DateTime.now();
      String two(int n) => n.toString().padLeft(2, '0');
      final name = '密码数据-${d.year}${two(d.month)}${two(d.day)}.pwm.json';
      final bytes = utf8.encode(payload);
      if (Platform.isAndroid || Platform.isIOS) {
        // 手机端默认走系统分享(可直发微信),同时存一份到临时目录
        final tmp = File(p.join((await getTemporaryDirectory()).path, name));
        await tmp.writeAsBytes(bytes);
        await SharePlus.instance.share(ShareParams(files: [XFile(tmp.path)]));
        Future.delayed(const Duration(minutes: 5), () { try { tmp.deleteSync(); } catch (_) {} });
        if (mounted) toast(context, '已调起发送面板,可用微信发给电脑后导入');
      } else {
        final saved = await FilePicker.saveFile(dialogTitle: '导出数据文件', fileName: name, bytes: bytes);
        if (saved != null && mounted) toast(context, '已导出加密数据,发到另一台设备后导入即可');
      }
    } catch (e) {
      setState(() => _error = '导出失败: $e');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _importFile() async {
    setState(() { _error = ''; _busy = true; });
    try {
      final files = await FilePicker.pickFiles();
      if (files.isEmpty) return;
      final f = files.first;
      final text = f.path != null ? await File(f.path!).readAsString() : utf8.decode(await f.readAsBytes());
      await _importPayloadText(text);
    } catch (e) {
      setState(() => _error = '导入失败: $e');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _importPayloadText(String text) async {
    final payload = jsonDecode(extractPayloadText(text)) as Map<String, dynamic>;
    if (payload['iv'] == null || payload['data'] == null) throw Exception('无法识别的数据格式');
    final store = VaultStore.instance;
    Vault? remote;
    // 1) 本机密钥直接解(同盐同密码,最快路径)
    try { remote = await CryptoService.decryptPayload(store.key!, payload); } catch (_) {}
    // 2) 同一主密码但盐不同:用内存中的会话密码按数据包的盐重新派生,免提示
    if (remote == null && store.sessionPw != null) {
      try {
        final k = await CryptoService.deriveKey(
            store.sessionPw!, base64Decode(payload['salt'] as String), payload['iterations'] as int?);
        remote = await CryptoService.decryptPayload(k, payload);
      } catch (_) {}
    }
    // 3) 确实是不同主密码:才询问
    if (remote == null) {
      final pw = await _askPassword();
      if (pw == null) throw Exception('已取消导入');
      final k = await CryptoService.deriveKey(
          pw, base64Decode(payload['salt'] as String), payload['iterations'] as int?);
      remote = await CryptoService.decryptPayload(k, payload);
    }
    final before = store.vault.entries.length;
    mergeVault(remote);
    await store.save();
    if (mounted) {
      toast(context, '同步完成:现有 ${store.vault.entries.length} 条(导入前 $before 条),已自动保存并刷新');
      Navigator.pop(context);
    }
  }

  Future<String?> _askPassword() {
    final c = TextEditingController();
    return showDialog<String>(context: context, builder: (ctx) => AlertDialog(
      title: const Text('该数据使用了不同的主密码'),
      content: TextField(controller: c, obscureText: true,
          decoration: const InputDecoration(labelText: '请输入它对应的主密码', border: OutlineInputBorder())),
      actions: [
        TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('取消')),
        FilledButton(onPressed: () => Navigator.pop(ctx, c.text), child: const Text('确定')),
      ]));
  }

  void _showQr() {
    showDialog(context: context, builder: (_) => const QrShowDialog());
  }

  Future<void> _scanQr() async {
    if (Platform.isAndroid || Platform.isIOS) {
      final result = await Navigator.of(context).push<String>(
          MaterialPageRoute(builder: (_) => const QrScanPage()));
      if (result != null) await _importPayloadText(result);
    } else {
      await _importQrImage();
    }
  }

  Future<void> _importQrImage() async {
    setState(() { _error = ''; _busy = true; });
    try {
      final files = await FilePicker.pickFiles(
          type: FileType.image, dialogTitle: '选择二维码图片(多帧请逐张上传)');
      if (files.isEmpty) return;
      final f = files.first;
      final bytes = f.path != null ? await File(f.path!).readAsBytes() : await f.readAsBytes();
      final text = decodeQrFromImage(bytes);
      if (text == null) { setState(() => _error = '未识别到二维码,请换更清晰、完整的图片'); return; }
      final feed = QrFeederHolder.instance.feeder.feed(text);
      if (feed.$3.isNotEmpty && !feed.$1) setState(() => _error = feed.$3);
      if (feed.$1) {
        QrFeederHolder.instance.feeder.reset();
        await _importPayloadText(feed.$2);
      }
    } catch (e) {
      setState(() => _error = '导入失败: $e');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final mobile = Platform.isAndroid || Platform.isIOS;
    return AlertDialog(
      title: const Text('同步数据'),
      content: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        if (mobile) ...[
          // 手机端:默认扫码导入电脑二维码;默认微信/分享发送文件到电脑
          FilledButton.icon(onPressed: _busy ? null : _scanQr,
              icon: const Icon(Icons.qr_code_scanner), label: const Text('扫二维码导入')),
          const SizedBox(height: 8),
          FilledButton.tonalIcon(onPressed: _busy ? null : _importFile,
              icon: const Icon(Icons.file_open), label: const Text('从文件导入')),
          const SizedBox(height: 8),
          OutlinedButton.icon(onPressed: _busy ? null : _showQr,
              icon: const Icon(Icons.qr_code), label: const Text('生成二维码(让对方扫)')),
          const SizedBox(height: 8),
          OutlinedButton.icon(onPressed: _busy ? null : _export,
              icon: const Icon(Icons.send), label: const Text('发送数据文件(微信等)')),
        ] else ...[
          // 电脑端:顺序同手机端——二维码导入,文件导入,二维码导出,文件导出
          FilledButton.icon(onPressed: _busy ? null : _scanQr,
              icon: const Icon(Icons.image_search), label: const Text('上传二维码图片导入')),
          const SizedBox(height: 8),
          FilledButton.tonalIcon(onPressed: _busy ? null : _importFile,
              icon: const Icon(Icons.file_open), label: const Text('导入数据文件(手机发来的)')),
          const SizedBox(height: 8),
          OutlinedButton.icon(onPressed: _busy ? null : _showQr,
              icon: const Icon(Icons.qr_code), label: const Text('生成二维码(让对方扫)')),
          const SizedBox(height: 8),
          OutlinedButton.icon(onPressed: _busy ? null : _export,
              icon: const Icon(Icons.upload_file), label: const Text('导出数据文件')),
        ],
        if (_error.isNotEmpty)
          Padding(padding: const EdgeInsets.only(top: 8),
              child: Text(_error, style: TextStyle(color: Theme.of(context).colorScheme.error))),
        const SizedBox(height: 8),
        Text('数据全程加密;两端用相同主密码自动合并。内容较多时二维码循环播放多帧,扫码端自动拼接。',
            style: Theme.of(context).textTheme.bodySmall),
      ]),
      actions: [TextButton(onPressed: () => Navigator.pop(context), child: const Text('关闭'))],
    );
  }
}

class QrFeederHolder {
  static final QrFeederHolder instance = QrFeederHolder();
  final QrCollector feeder = QrCollector();
}

/* ==================== 二维码展示(多帧循环) ==================== */

class QrShowDialog extends StatefulWidget {
  const QrShowDialog({super.key});
  @override
  State<QrShowDialog> createState() => _QrShowDialogState();
}

class _QrShowDialogState extends State<QrShowDialog> {
  List<String> _frames = [];
  int _idx = 0;
  Timer? _timer;
  String _error = '';

  @override
  void initState() {
    super.initState();
    buildSyncPayload().then((payload) {
      final frames = buildQrFrames(payload);
      setState(() => _frames = frames);
      if (frames.length > 1) {
        _timer = Timer.periodic(const Duration(milliseconds: 900), (_) {
          if (mounted) setState(() => _idx = (_idx + 1) % _frames.length);
        });
      }
    }).catchError((e) => setState(() => _error = '$e'));
  }

  @override
  void dispose() { _timer?.cancel(); super.dispose(); }

  Future<void> _saveQrImage() async {
    if (_frames.isEmpty) return;
    _timer?.cancel(); // 暂停轮播,保存当前帧
    try {
      final painter = QrPainter(
          data: _frames[_idx], version: QrVersions.auto,
          errorCorrectionLevel: QrErrorCorrectLevel.M, gapless: true);
      final pic = await painter.toImage(800);
      final bd = await pic.toByteData(format: ui.ImageByteFormat.png);
      if (bd == null) throw Exception('图片生成失败');
      final bytes = bd.buffer.asUint8List();
      final name = _frames.length > 1
          ? '同步二维码-第${_idx + 1}帧-共${_frames.length}帧.png'
          : '同步二维码.png';
      if (Platform.isAndroid || Platform.isIOS) {
        final tmp = File(p.join((await getTemporaryDirectory()).path, name));
        await tmp.writeAsBytes(bytes);
        await SharePlus.instance.share(ShareParams(files: [XFile(tmp.path)]));
        Future.delayed(const Duration(minutes: 5), () { try { tmp.deleteSync(); } catch (_) {} });
      } else {
        final saved = await FilePicker.saveFile(dialogTitle: '保存二维码图片', fileName: name, bytes: bytes);
        if (saved != null && mounted) toast(context, '二维码图片已保存');
      }
    } catch (e) {
      if (mounted) toast(context, '保存失败: $e');
    }
  }

  @override
  Widget build(BuildContext context) => AlertDialog(
        title: const Text('加密数据二维码'),
        content: Column(mainAxisSize: MainAxisSize.min, children: [
          if (_error.isNotEmpty) Text(_error, style: TextStyle(color: Theme.of(context).colorScheme.error)),
          if (_frames.isEmpty && _error.isEmpty) const CircularProgressIndicator(),
          if (_frames.isNotEmpty)
            Container(
              color: Colors.white, padding: const EdgeInsets.all(8),
              child: QrImageView(data: _frames[_idx], size: 260, errorCorrectionLevel: QrErrorCorrectLevel.M)),
          const SizedBox(height: 8),
          Text(_frames.length > 1
              ? '第 ${_idx + 1}/${_frames.length} 帧,循环播放中;对方持续扫描直至收齐'
              : '让对方用"扫码导入"扫描此码', style: Theme.of(context).textTheme.bodySmall),
        ]),
        actions: [
          TextButton.icon(onPressed: _frames.isEmpty ? null : _saveQrImage,
              icon: const Icon(Icons.save_alt, size: 18), label: const Text('保存图片')),
          TextButton(onPressed: () => Navigator.pop(context), child: const Text('关闭')),
        ],
      );
}

/* ==================== 摄像头扫码(手机端) ==================== */

class QrScanPage extends StatefulWidget {
  const QrScanPage({super.key});
  @override
  State<QrScanPage> createState() => _QrScanPageState();
}

class _QrScanPageState extends State<QrScanPage> {
  final _collector = QrCollector();
  final _controller = MobileScannerController();
  String _info = '对准二维码…';
  bool _done = false;

  void _onDetect(BarcodeCapture capture) {
    if (_done) return;
    for (final b in capture.barcodes) {
      final raw = b.rawValue;
      if (raw == null) continue;
      final r = _collector.feed(raw);
      if (r.$3.isNotEmpty) setState(() => _info = r.$3);
      if (r.$1) {
        _done = true;
        _controller.stop();
        Navigator.pop(context, r.$2);
        return;
      }
    }
  }

  @override
  void dispose() { _controller.dispose(); super.dispose(); }

  @override
  Widget build(BuildContext context) => Scaffold(
        appBar: AppBar(title: const Text('扫码导入')),
        body: Column(children: [
          Expanded(child: MobileScanner(controller: _controller, onDetect: _onDetect)),
          Padding(padding: const EdgeInsets.all(16), child: Text(_info)),
        ]),
      );
}

/* ==================== 二维码图片解码(电脑端,纯 Dart) ==================== */

String? decodeQrFromImage(Uint8List bytes) {
  final image = img.decodeImage(bytes);
  if (image == null) return null;
  final rgba = image.getBytes(order: img.ChannelOrder.rgba);
  final pixels = Int32List(image.width * image.height);
  for (var i = 0, j = 0; i < rgba.length; i += 4, j++) {
    pixels[j] = (rgba[i + 3] << 24) | (rgba[i] << 16) | (rgba[i + 1] << 8) | rgba[i + 2];
  }
  final source = zq.RGBLuminanceSource(image.width, image.height, pixels);
  final bitmap = zq.BinaryBitmap(zq.HybridBinarizer(source));
  try {
    return zq.QRCodeReader().decode(bitmap).text;
  } catch (_) {
    return null;
  }
}
