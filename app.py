"""
VulnFlask - 보안 교육/침투 테스트 실습용 취약 웹 애플리케이션
=============================================================
⚠ WARNING: 이 애플리케이션은 의도적으로 취약하게 설계되었습니다.
           실제 서비스 환경에 절대 배포하지 마세요.
           교육 및 CTF, 펜테스트 실습 목적으로만 사용하세요.

포함된 취약점:
  - SQL Injection (로그인 우회, UNION, Blind)
  - XSS (Reflected, Stored, DOM)
  - Command Injection
  - CSRF (토큰 없는 상태 변경)
  - IDOR (Insecure Direct Object Reference)
  - 파일 업로드 취약점 (확장자 무검증)
  - 민감 정보 노출 (환경변수, 스택트레이스, API 키)
  - 취약한 인증 (하드코딩 자격증명, 약한 세션)
  - Path Traversal
  - Open Redirect
  - SSRF
  - XXE (Python 내장 sax 파서 사용)
  - 디렉토리 리스팅
"""

import os
import sqlite3
import subprocess
import requests
import json
import io
import xml.sax
from functools import wraps
from flask import (
    Flask, request, render_template, redirect,
    session, jsonify, send_from_directory,
    make_response, url_for, render_template_string
)

# ──────────────────────────────────────────────────
# 앱 설정 (의도적으로 취약한 설정)
# ──────────────────────────────────────────────────
app = Flask(__name__)

# 취약: 약하고 하드코딩된 시크릿 키
app.secret_key = "mysecretkey123"

# 취약: 디버그 모드 활성화 → 스택트레이스 외부 노출
app.config["DEBUG"] = True

# 취약: 업로드 폴더 (확장자 제한 없음)
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "uploads")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# 취약: 하드코딩된 자격증명 및 API 키
HARDCODED_CREDS = {
    "admin":     "admin123",
    "user":      "password",
    "test":      "test",
    "developer": "dev2024!",
}

# 취약: 소스코드에 노출된 민감 정보
# 수정된 SECRET_CONFIG
SECRET_CONFIG = {
    "DB_PASS":        os.environ.get("DB_PASS", "Sup3rS3cr3t!"),
    "AWS_KEY":        os.environ.get("AWS_KEY", "AKIAIOSFODNN7EXAMPLE"),
    "AWS_SECRET":     os.environ.get("AWS_SECRET", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    # 실제 키 대신 테스트용 더미 키를 기본값으로 사용하세요.
    "STRIPE_SECRET":  os.environ.get("STRIPE_SECRET", "sk_test_fake_key_for_training_only"),
    "JWT_SECRET":     os.environ.get("JWT_SECRET", "jwt_secret_key_123"),
    "INTERNAL_API":   "http://internal-api.company.local/v1",
}

DB_PATH = os.path.join(os.path.dirname(__file__), "vulnshop.db")

# ──────────────────────────────────────────────────
# DB 초기화 (취약한 스키마 + 시드 데이터)
# ──────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email    TEXT,
            role     TEXT DEFAULT 'user',
            ssn      TEXT,
            phone    TEXT
        );

        CREATE TABLE IF NOT EXISTS products (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL,
            description TEXT,
            price       INTEGER
        );

        CREATE TABLE IF NOT EXISTS orders (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER,
            product_id  INTEGER,
            amount      INTEGER,
            card_number TEXT,
            address     TEXT
        );

        CREATE TABLE IF NOT EXISTS comments (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            content TEXT,
            created TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS secret_flags (
            id   INTEGER PRIMARY KEY,
            flag TEXT
        );
    """)

    # 시드 데이터
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        users = [
            ("admin",     "admin123",  "admin@vulnshop.com",  "admin", "900101-1234567", "010-0000-0001"),
            ("alice",     "alice456",  "alice@gmail.com",     "user",  "950515-2345678", "010-1111-2222"),
            ("bob",       "bob789",    "bob@naver.com",       "user",  "881231-1111111", "010-3333-4444"),
            ("developer", "dev2024!",  "dev@vulnshop.com",    "dev",   "920303-2222222", "010-5555-6666"),
        ]
        c.executemany(
            "INSERT INTO users (username,password,email,role,ssn,phone) VALUES (?,?,?,?,?,?)",
            users
        )

    c.execute("SELECT COUNT(*) FROM products")
    if c.fetchone()[0] == 0:
        products = [
            ("갤럭시 S25",  "삼성 최신 플래그십",   1200000),
            ("아이폰 16",   "애플 최신 스마트폰",   1500000),
            ("맥북 프로",   "M3 칩 탑재 노트북",   3500000),
            ("갤럭시 탭",   "안드로이드 태블릿",     800000),
            ("에어팟 프로", "노이즈 캔슬링 이어폰",  350000),
        ]
        c.executemany(
            "INSERT INTO products (name,description,price) VALUES (?,?,?)",
            products
        )

    c.execute("SELECT COUNT(*) FROM orders")
    if c.fetchone()[0] == 0:
        orders = [
            (1, 3, 3500000, "4532-1234-5678-9876", "서울 강남구 테헤란로 1"),
            (2, 1, 1200000, "5412-0000-1111-2222", "부산 해운대구 해운대로 2"),
            (3, 2, 1500000, "4111-9999-8888-7777", "대구 수성구 동대구로 3"),
        ]
        c.executemany(
            "INSERT INTO orders (user_id,product_id,amount,card_number,address) VALUES (?,?,?,?,?)",
            orders
        )

    c.execute("SELECT COUNT(*) FROM secret_flags")
    if c.fetchone()[0] == 0:
        c.execute("INSERT INTO secret_flags VALUES (1, 'FLAG{sql_injection_master}')")
        c.execute("INSERT INTO secret_flags VALUES (2, 'FLAG{xss_pop_goes_the_alert}')")
        c.execute("INSERT INTO secret_flags VALUES (3, 'FLAG{command_injection_rce}')")

    conn.commit()
    conn.close()


def get_db():
    return sqlite3.connect(DB_PATH)


# ──────────────────────────────────────────────────
# 헬퍼
# ──────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated


# ──────────────────────────────────────────────────
# 메인 / 인덱스
# ──────────────────────────────────────────────────
@app.route("/")
def index():
    # 취약: 세션에 민감 정보 저장 후 노출
    return render_template("index.html",
                           user=session.get("user"),
                           config=SECRET_CONFIG)


# ──────────────────────────────────────────────────
# 1. SQL Injection — 로그인
# ──────────────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    query_shown = None

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # 취약: 파라미터 바인딩 없이 문자열 직접 연결
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        query_shown = query

        try:
            conn = get_db()
            c = conn.cursor()
            c.execute(query)          # ← SQLi 취약 지점
            user = c.fetchone()
            conn.close()

            if user:
                session["user"]    = user[1]
                session["user_id"] = user[0]
                session["role"]    = user[4]
                return redirect("/dashboard")
            else:
                error = "아이디 또는 비밀번호가 틀렸습니다."
        except Exception as e:
            # 취약: 상세 에러 메시지 노출
            error = f"DB 오류: {str(e)}\n쿼리: {query}"

    return render_template("login.html", error=error, query=query_shown)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ──────────────────────────────────────────────────
# 2. SQL Injection — 상품 검색
# ──────────────────────────────────────────────────
@app.route("/products")
def products():
    search = request.args.get("search", "")
    product_id = request.args.get("id", "")
    results = []
    query_shown = ""
    error = None

    conn = get_db()
    c = conn.cursor()

    if product_id:
        # 취약: UNION / Blind SQLi 가능
        query_shown = f"SELECT id,name,description,price FROM products WHERE id={product_id}"
        try:
            c.execute(query_shown)
            results = c.fetchall()
        except Exception as e:
            error = str(e)
    elif search:
        # 취약: LIKE 구문에 직접 삽입
        query_shown = f"SELECT id,name,description,price FROM products WHERE name LIKE '%{search}%'"
        try:
            c.execute(query_shown)
            results = c.fetchall()
        except Exception as e:
            error = str(e)
    else:
        c.execute("SELECT id,name,description,price FROM products")
        results = c.fetchall()

    conn.close()
    return render_template("products.html",
                           results=results,
                           query=query_shown,
                           search=search,
                           error=error)


# ──────────────────────────────────────────────────
# 3. XSS — 게시판 (Reflected + Stored)
# ──────────────────────────────────────────────────
@app.route("/board", methods=["GET", "POST"])
def board():
    # Reflected XSS: URL 파라미터를 그대로 렌더링
    search = request.args.get("search", "")

    conn = get_db()
    c = conn.cursor()

    if request.method == "POST":
        content = request.form.get("content", "")
        user_id = session.get("user_id", 0)
        # 취약: 이스케이프 없이 DB 저장 → Stored XSS
        c.execute("INSERT INTO comments (user_id, content) VALUES (?, ?)", (user_id, content))
        conn.commit()

    c.execute("""
        SELECT comments.id, users.username, comments.content, comments.created
        FROM comments
        LEFT JOIN users ON comments.user_id = users.id
        ORDER BY comments.id DESC
    """)
    comments = c.fetchall()
    conn.close()

    # 취약: search 값을 Jinja2 |safe 필터로 렌더링
    return render_template("board.html", comments=comments, search=search)


# ──────────────────────────────────────────────────
# 4. IDOR — 사용자/주문 직접 접근
# ──────────────────────────────────────────────────
@app.route("/api/users/<int:user_id>")
def api_user(user_id):
    # 취약: 로그인 확인 없음 + 권한 검증 없음
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id,username,email,role,ssn,phone FROM users WHERE id=?", (user_id,))
    row = c.fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "사용자 없음"}), 404

    return jsonify({
        "id": row[0], "username": row[1], "email": row[2],
        "role": row[3], "ssn": row[4], "phone": row[5],
        "note": "IDOR: 권한 검증 없이 누구나 조회 가능"
    })


@app.route("/api/orders/<int:order_id>")
def api_order(order_id):
    # 취약: 주문 소유자 검증 없음
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM orders WHERE id=?", (order_id,))
    row = c.fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "주문 없음"}), 404

    return jsonify({
        "id": row[0], "user_id": row[1], "product_id": row[2],
        "amount": row[3], "card_number": row[4], "address": row[5],
        "note": "IDOR: 타인의 결제 정보(카드번호, 주소) 열람 가능"
    })


# ──────────────────────────────────────────────────
# 5. 파일 업로드 취약점
# ──────────────────────────────────────────────────
@app.route("/upload", methods=["GET", "POST"])
def upload():
    message = None
    uploaded_path = None

    if request.method == "POST":
        f = request.files.get("file")
        if f and f.filename:
            # 취약: 확장자/MIME 검증 전혀 없음
            filename = f.filename          # 취약: 원본 파일명 그대로 사용
            save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            f.save(save_path)
            uploaded_path = f"/uploads/{filename}"
            message = f"업로드 완료: {uploaded_path}"

    # 취약: 업로드 디렉토리 목록 노출
    files = os.listdir(app.config["UPLOAD_FOLDER"])
    return render_template("upload.html", message=message,
                           uploaded_path=uploaded_path, files=files)


@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    # 취약: Path Traversal 가능 (../../../etc/passwd)
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


# ──────────────────────────────────────────────────
# 6. Command Injection
# ──────────────────────────────────────────────────
@app.route("/ping", methods=["GET", "POST"])
def ping():
    result = None
    host = ""

    if request.method == "POST":
        host = request.form.get("host", "")
        # 취약: 사용자 입력을 shell=True로 직접 실행
        try:
            cmd = f"ping -c 3 {host}"
            result = subprocess.check_output(
                cmd, shell=True, stderr=subprocess.STDOUT,
                timeout=10, text=True
            )
        except subprocess.TimeoutExpired:
            result = "타임아웃"
        except subprocess.CalledProcessError as e:
            result = e.output
        except Exception as e:
            result = str(e)

    return render_template("ping.html", result=result, host=host)


# ──────────────────────────────────────────────────
# 7. SSRF
# ──────────────────────────────────────────────────
@app.route("/fetch", methods=["GET", "POST"])
def fetch_url():
    result = None
    url = ""

    if request.method == "POST":
        url = request.form.get("url", "")
        # 취약: 내부 URL 필터링 없이 서버에서 직접 요청
        try:
            resp = requests.get(url, timeout=5)
            result = resp.text[:3000]
        except Exception as e:
            result = f"오류: {str(e)}"

    return render_template("fetch.html", result=result, url=url)


# ──────────────────────────────────────────────────
# 8. XXE (XML External Entity) - 내장 sax 모듈 사용
# ──────────────────────────────────────────────────
class VulnXXEHandler(xml.sax.ContentHandler):
    def __init__(self):
        self.parsed_data = ""
        self.current_tag = ""

    def startElement(self, tag, attributes):
        self.current_tag = tag

    def characters(self, content):
        if content.strip():
            self.parsed_data += f"[{self.current_tag}] {content}\n"

    def endElement(self, tag):
        self.current_tag = ""

@app.route("/xxe", methods=["GET", "POST"])
def xxe():
    result = None
    xml_input = ""

    if request.method == "POST":
        xml_input = request.form.get("xml", "")
        try:
            # 취약: 외부 엔티티(External General Entities) 허용 설정
            parser = xml.sax.make_parser()
            parser.setFeature(xml.sax.handler.feature_external_ges, True)
            
            handler = VulnXXEHandler()
            parser.setContentHandler(handler)
            
            # 파싱 실행 (외부 엔티티가 포함되어 있다면 여기서 시스템 파일을 읽어옵니다)
            parser.parse(io.StringIO(xml_input))
            result = handler.parsed_data
        except Exception as e:
            result = f"XML 파싱 오류: {str(e)}"

    # 윈도우 환경 테스트를 위해 c:/windows/win.ini를 기본 페이로드로 세팅
    default_xml = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<root>
  <data>&xxe;</data>
</root>"""

    return render_template("xxe.html", result=result,
                           xml_input=xml_input or default_xml)


# ──────────────────────────────────────────────────
# 9. CSRF — 비밀번호 변경
# ──────────────────────────────────────────────────
@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    message = None

    if request.method == "POST":
        new_password = request.form.get("new_password", "")
        # 취약: CSRF 토큰 검증 없음
        conn = get_db()
        c = conn.cursor()
        c.execute("UPDATE users SET password=? WHERE username=?",
                  (new_password, session["user"]))
        conn.commit()
        conn.close()
        message = f"비밀번호가 '{new_password}'로 변경되었습니다. (CSRF 토큰 없음)"

    return render_template("change_password.html", message=message)


# ──────────────────────────────────────────────────
# 10. Open Redirect
# ──────────────────────────────────────────────────
@app.route("/redirect")
def open_redirect():
    # 취약: next 파라미터를 검증 없이 리다이렉트
    next_url = request.args.get("next", "/")
    return redirect(next_url)


# ──────────────────────────────────────────────────
# 11. Path Traversal — 파일 읽기
# ──────────────────────────────────────────────────
@app.route("/file")
def read_file():
    # 취약: 경로 정규화 없이 직접 파일 읽기
    filename = request.args.get("name", "readme.txt")
    base_dir = os.path.join(os.path.dirname(__file__), "static")
    filepath = os.path.join(base_dir, filename)  # ← ../../../etc/passwd 가능

    try:
        with open(filepath, "r") as f:
            content = f.read()
        return render_template("file.html", content=content, filename=filename)
    except Exception as e:
        # 취약: 에러 메시지에 경로 노출
        return render_template("file.html",
                               content=f"오류: {str(e)}\n경로: {filepath}",
                               filename=filename)


# ──────────────────────────────────────────────────
# 12. 민감 정보 노출 엔드포인트
# ──────────────────────────────────────────────────
@app.route("/debug")
def debug_info():
    # 취약: 환경변수, 설정, 세션 정보 그대로 노출
    return jsonify({
        "environment": dict(os.environ),
        "secret_config": SECRET_CONFIG,
        "session": dict(session),
        "hardcoded_creds": HARDCODED_CREDS,
        "db_path": DB_PATH,
        "python_path": os.sys.path,
    })


@app.route("/api/config")
def api_config():
    # 취약: API 키 등 민감 정보 노출
    return jsonify(SECRET_CONFIG)


# ──────────────────────────────────────────────────
# 13. 템플릿 인젝션 (SSTI)
# ──────────────────────────────────────────────────
@app.route("/greet")
def greet():
    name = request.args.get("name", "Guest")
    # 취약: 사용자 입력을 render_template_string에 직접 전달
    # 테스트: ?name={{7*7}} → 49 출력
    # 테스트: ?name={{config}} → 설정 정보 노출
    template = f"<h2>안녕하세요, {name}!</h2>"
    return render_template_string(template)


# ──────────────────────────────────────────────────
# 14. 대시보드
# ──────────────────────────────────────────────────
@app.route("/dashboard")
@login_required
def dashboard():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id,username,email,role FROM users")
    users = c.fetchall()
    c.execute("SELECT id,name,price FROM products")
    products_list = c.fetchall()
    conn.close()
    return render_template("dashboard.html",
                           users=users, products=products_list)


# ──────────────────────────────────────────────────
# 애플리케이션 실행
# ──────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    # 취약: 모든 인터페이스에서 수신 + 디버그 모드
    app.run(host="0.0.0.0", port=5000, debug=True)