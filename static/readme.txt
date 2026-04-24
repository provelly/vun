VulnFlask Static Files
======================
이 디렉토리의 파일은 /file?name=<파일명> 으로 접근 가능합니다.

Path Traversal 테스트:
  /file?name=../../../etc/passwd
  /file?name=../app.py
