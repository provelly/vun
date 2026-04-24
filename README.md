# VulnFlask — 취약 웹 애플리케이션

> ⚠ **경고**: 이 앱은 보안 교육/펜테스트 실습 전용입니다.
> 실제 서버에 배포하거나 인터넷에 노출하지 마세요.

---

## 포함된 취약점 (OWASP Top 10 기반)

| # | 취약점 | 엔드포인트 | 테스트 페이로드 |
|---|--------|-----------|----------------|
| 1 | **SQL Injection** | `/login`, `/products` | `admin'--` / `' OR '1'='1` |
| 2 | **XSS (Reflected/Stored)** | `/board` | `<script>alert(1)</script>` |
| 3 | **IDOR** | `/api/users/<id>`, `/api/orders/<id>` | ID 숫자 변경 |
| 4 | **파일 업로드** | `/upload` | `.php`, `.py` 등 업로드 |
| 5 | **Command Injection** | `/ping` | `127.0.0.1; id` |
| 6 | **SSRF** | `/fetch` | `http://169.254.169.254/` |
| 7 | **XXE** | `/xxe` | `<!ENTITY xxe SYSTEM "file:///etc/passwd">` |
| 8 | **SSTI (Jinja2)** | `/greet?name=` | `{{7*7}}`, `{{config}}` |
| 9 | **Path Traversal** | `/file?name=` | `../../../etc/passwd` |
| 10 | **CSRF** | `/change-password` | 토큰 없는 POST |
| 11 | **Open Redirect** | `/redirect?next=` | `https://evil.com` |
| 12 | **정보 노출** | `/debug`, `/api/config` | GET 요청으로 확인 |

---

## 설치 및 실행

```bash
# 1. 의존성 설치
pip install -r requirements.txt

# 2. 앱 실행
python app.py

# 3. 브라우저 접속
http://localhost:5000
```

---

## 디렉토리 구조

```
vulnapp/
├── app.py              # 메인 Flask 앱 (모든 취약 라우트)
├── requirements.txt
├── vulnshop.db         # SQLite DB (최초 실행 시 자동 생성)
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── login.html       # SQLi
│   ├── products.html    # SQLi
│   ├── board.html       # XSS
│   ├── upload.html      # 파일 업로드
│   ├── ping.html        # Command Injection
│   ├── fetch.html       # SSRF
│   ├── xxe.html         # XXE
│   ├── file.html        # Path Traversal
│   ├── change_password.html  # CSRF
│   └── dashboard.html   # IDOR
├── static/
│   └── readme.txt
└── uploads/             # 업로드 파일 저장 (검증 없음)
```

---

## 웹 스캐너 테스트 권장 도구

- **Burp Suite** — 프록시 + 스캐너
- **OWASP ZAP** — 자동 취약점 스캔
- **sqlmap** — `sqlmap -u "http://localhost:5000/products?id=1" --dbs`
- **nikto** — `nikto -h http://localhost:5000`
- **gobuster** — 디렉토리 열거

---

## 하드코딩 계정

| 계정 | 비밀번호 | 권한 |
|------|---------|------|
| admin | admin123 | ADMIN |
| user | password | USER |
| test | test | USER |
| developer | dev2024! | DEV |
