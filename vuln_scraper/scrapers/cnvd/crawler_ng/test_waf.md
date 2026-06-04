WAF REQUEST

```http
GET / HTTP/2
Host: www.cnvd.org.cn
Sec-Ch-Ua: "Not-A.Brand";v="24", "Chromium";v="146"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Linux"
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Priority: u=0, i
```

WAF RESPONSE

```http
HTTP/2 521 Web Server Is Down
Server: nginx
Date: Wed, 03 Jun 2026 08:53:44 GMT
X-Via-Jsl: 887b0cd,-
Set-Cookie: __jsluid_s=a3aa9924b2a5fb845869029c3e9ed9b8; max-age=31536000; path=/; HttpOnly; SameSite=None; secure

<script>document.cookie=('_')+('_')+('j')+('s')+('l')+('_')+('c')+('l')+('e')+('a')+('r')+('a')+('n')+('c')+('e')+('_')+('s')+('=')+(+!+[]+'')+(3+4+'')+(-~[7]+'')+(~~false+'')+(-~(3)+'')+(-~[6]+'')+(-~[5]+'')+(8+'')+(-~1+'')+((2<<1)+'')+('.')+(3+6+'')+(5+'')+((1<<2)+'')+('|')+('-')+(-~[]+'')+('|')+((1+[0])/[2]+'')+('k')+('g')+('Z')+('f')+('J')+('N')+('a')+([3]*(3)+'')+((+false)+'')+('a')+('e')+('F')+('c')+('J')+('F')+('W')+('S')+('i')+('j')+('I')+('C')+('W')+('u')+('X')+('q')+('M')+('%')+(3+'')+('D')+(';')+(' ')+('M')+('a')+('x')+('-')+('a')+('g')+('e')+('=')+(1+2+'')+(2+4+'')+((+[])+'')+((+[])+'')+(';')+(' ')+('P')+('a')+('t')+('h')+('=')+('/')+(';')+(' ')+('S')+('a')+('m')+('e')+('S')+('i')+('t')+('e')+('=')+('N')+('o')+('n')+('e')+(';')+(' ')+('S')+('e')+('c')+('u')+('r')+('e');location.href=location.pathname+location.search</script>
```