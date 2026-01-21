# SQL Injection
## HTML代码(网页代码)
        <form action="#" method="GET">
			<p>
				User ID:
				<input type="text" size="15" name="id">
				<input type="submit" name="Submit" value="Submit">
			</p>

		</form>

✨ action="#",将数据提交到当前页面

# DVWA SQL注入漏洞分析（Low级别）

## 1. 漏洞概述
**SQL注入**是一种将恶意SQL代码插入到应用程序的输入参数中，从而在后台数据库执行这些恶意代码的攻击技术。DVWA（Damn Vulnerable Web Application）的Low级别中，用户输入未经过任何过滤直接拼接到SQL语句，导致严重的SQL注入漏洞。

## 2. 漏洞代码分析

### 表格 1: 主程序流程分析
| 代码行 | 代码 | 描述 | 安全问题 |
| :--- | :--- | :--- | :--- |
| **1-3** | `if( isset( $_REQUEST[ 'Submit' ] ) ) {` | 检查表单是否提交 | 无 |
| **4-5** | `$id = $_REQUEST[ 'id' ];` | 直接获取用户输入的id参数 | ❌ **高危**：无任何过滤 |
| **8-9** | `$query = "SELECT ... WHERE user_id = '$id';"` | SQL查询字符串拼接 | ❌ **注入点**：用户输入直接拼接 |

### 表格 2: MySQL分支漏洞详情
| 代码部分 | 功能 | 风险等级 | 修复建议 |
| :--- | :--- | :--- | :--- |
| `mysqli_query(...) or die(...)` | 执行SQL查询 | 🔴 **高危** | 1. 使用预处理语句<br>2. 禁止显示详细错误 |
| `while( $row = mysqli_fetch_assoc(...))` | 遍历查询结果 | 🟢 **安全** | 正常数据处理逻辑 |
| 错误信息输出 | 显示数据库错误 | 🟡 **中危** | 生产环境应隐藏错误详情 |

### 表格 3: SQLite分支对比
| 特性 | MySQL版本 | SQLite版本 | 差异说明 |
| :--- | :--- | :--- | :--- |
| **连接方式** | `$GLOBALS["___mysqli_ston"]` | `$sqlite_db_connection` | 全局变量名不同 |
| **查询执行** | `mysqli_query()` | `$sqlite_db_connection->query()` | 面向过程 vs 面向对象 |
| **错误处理** | `or die()`直接输出 | `try-catch`异常捕获 | SQLite错误处理更规范 |
| **结果获取** | `mysqli_fetch_assoc()` | `$results->fetchArray()` | API接口不同 |

## 3. 漏洞利用方法

### 表格 4: 常见注入Payload
| 攻击类型 | 输入示例 | 生成的SQL语句 | 攻击效果 |
| :--- | :--- | :--- | :--- |
| **永真条件** | `1' OR '1'='1` | `...WHERE user_id = '1' OR '1'='1'` | 返回所有用户数据 |
| **联合查询** | `1' UNION SELECT user, password FROM users-- ` | `...WHERE user_id = '1' UNION SELECT user, password FROM users-- '` | 获取其他表数据 |
| **注释绕过** | `1'-- ` | `...WHERE user_id = '1'-- '` | 注释掉后续代码 |
| **错误注入** | `1' AND 1=convert(int,@@version)--` | `...WHERE user_id = '1' AND 1=convert(int,@@version)--'` | 获取数据库信息 |

## 4. 修复方案对比

### 表格 5: 安全修复方案
| 方案 | 实现方法 | 优点 | 缺点 |
| :--- | :--- | :--- | :--- |
| **预处理语句** | 使用参数化查询分离数据与SQL逻辑 | 1. 彻底防止SQL注入<br>2. 代码清晰易维护 | 1. 需修改代码结构<br>2. 学习曲线稍高 |
| **输入过滤** | 对用户输入进行验证和过滤 | 1. 简单易实现<br>2. 可结合业务逻辑 | 1. 可能被绕过<br>2. 需针对不同类型处理 |
| **最小权限** | 数据库用户使用最小必要权限 | 1. 限制攻击影响范围<br>2. 符合安全最佳实践 | 1. 权限配置复杂<br>2. 需DBA配合 |

## 5. 修复代码示例

### 方案1: 使用预处理语句（MySQL）
  $stmt = $GLOBALS["___mysqli_ston"]->prepare    ("SELECT first_name, last_name FROM users WHERE user_id = ?");
$stmt->bind_param("s", $id);
$stmt->execute();
$result = $stmt->get_result();

while( $row = $result->fetch_assoc() ) {
    $first = $row["first_name"];
    $last  = $row["last_name"];
    echo "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
}

  $stmt->close();

### 方案2: 输入过滤（简单场景）
if($id <= 0) {
    echo "Invalid ID";
    exit();
}

$query  = "SELECT first_name, last_name FROM users WHERE user_id = " . $id . ";";
$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>Database error</pre>' );

// ... 其他代码

## 6. 防御建议
1. **始终使用预处理语句**或参数化查询
2. **对用户输入进行严格验证**，使用白名单机制
3. **实施最小权限原则**，数据库用户只拥有必要权限
4. **隐藏详细错误信息**，生产环境禁用详细错误显示
5. **定期进行安全审计**和代码审查
6. **使用Web应用防火墙(WAF)** 作为额外防护层

## 7. 漏洞影响等级
| 风险类型 | 影响程度 | 修复优先级 |
| :--- | :--- | :--- |
| **数据泄露** | 🔴 高 | 立即修复 |
| **数据篡改** | 🔴 高 | 立即修复 |
| **权限提升** | 🟡 中 | 高优先级 |
| **系统信息泄露** | 🟡 中 | 中优先级 |

---

**分析日期**: 2026年1月22日  
**安全等级**: 高危  
**修复状态**: 未修复  


