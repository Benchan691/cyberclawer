```bash
┌──(.venv)─(kali㉿kali)-[~/crawlers/cnvd-ng]
└─$ python3 getter.py --debug           
2026-06-03 05:14:01,132 [WARNING] 找不到 session_cookies.json，跳過載入
2026-06-03 05:14:01,133 [INFO] [1] GET https://www.cnvd.org.cn
2026-06-03 05:14:01,134 [DEBUG] Starting new HTTPS connection (1): www.cnvd.org.cn:443
2026-06-03 05:14:01,626 [DEBUG] https://www.cnvd.org.cn:443 "GET / HTTP/1.1" 521 None
2026-06-03 05:14:01,626 [DEBUG] 狀態 521 | cookies: {'__jsluid_s': '4f708f4d25b5123ad61b029501006ac8'}
2026-06-03 05:14:01,626 [INFO] [JSL] 解析 521 挑戰…
2026-06-03 05:14:01,640 [DEBUG] Encoding detection: utf_8 will be used as a fallback match
2026-06-03 05:14:01,640 [DEBUG] Encoding detection: Found utf_8 as plausible (best-candidate) for content. With 0 alternatives.
2026-06-03 05:14:01,640 [DEBUG] JSL eval → __jsl_clearance_s=1780478041.594|-1|X70LrmFsjcuh9IZ7PVNiKYJ4
2026-06-03 05:14:01,641 [DEBUG] 已注入 __jsl_clearance_s=1780478041.594|-1|X7…
2026-06-03 05:14:01,698 [DEBUG] https://www.cnvd.org.cn:443 "GET / HTTP/1.1" 521 12040
2026-06-03 05:14:01,699 [DEBUG] 重試後狀態 521
2026-06-03 05:14:01,699 [INFO] ── 第 1 次嘗試 ──────────────────────
2026-06-03 05:14:01,699 [DEBUG] [captcha] GET c=1 s=02332431908
2026-06-03 05:14:01,744 [DEBUG] https://www.cnvd.org.cn:443 "GET /cdn-cgi/captcha/v2/captcha/image?c=1&s=02332431908 HTTP/1.1" 200 None
2026-06-03 05:14:01,744 [DEBUG] 驗證碼圖片 → captcha.png
2026-06-03 05:14:01,757 [DEBUG] STREAM b'IHDR' 16 13
2026-06-03 05:14:01,758 [DEBUG] STREAM b'IDAT' 41 1849
2026-06-03 05:14:01,775 [DEBUG] [ocr] '地球'
2026-06-03 05:14:01,780 [INFO] [match] OCR='地球' ← 符合條件，準備提交
2026-06-03 05:14:01,780 [INFO] [submit] ans='地球'  sec(前8)=edfeacc2…
2026-06-03 05:14:01,824 [DEBUG] https://www.cnvd.org.cn:443 "POST /cdn-cgi/captcha/v2/captcha/image HTTP/1.1" 200 13
2026-06-03 05:14:01,825 [INFO] [submit] ✓ 驗證成功
2026-06-03 05:14:01,825 [INFO] Cookie 已儲存 → session_cookies.json（2 個）
2026-06-03 05:14:01,881 [DEBUG] https://www.cnvd.org.cn:443 "GET / HTTP/1.1" 200 11950
2026-06-03 05:14:01,882 [INFO] [operate] 自定義操作
2026-06-03 05:14:01,882 [INFO] 完成。Cookie → /home/kali/crawlers/cnvd-ng/session_cookies.json

============================================================
[DEBUG] 最終 URL   : https://www.cnvd.org.cn/
[DEBUG] 狀態碼     : 200
[DEBUG] Cookie     : {'__jsluid_s': '4f708f4d25b5123ad61b029501006ac8', '__jsl_clearance_s': '1780478041.793|1|7sa5Wog2xzFjEs%2FvGkwljW6RV3c%3D'}
[DEBUG] 回應前 200 字：



<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html>
<head>
        <title>国家信息安全漏洞共享平台</title>
        <script type="text/javas
============================================================

```