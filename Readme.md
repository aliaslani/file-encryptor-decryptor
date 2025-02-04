راهنمای فارسی رمزنگار:
### توضیح گام به گام کد (به زبان ساده):

این کد یک سیستم رمزنگاری به نام **Envelope Encryption** را پیاده‌سازی می‌کند که در آن:
1. برای هر فایل یک **کلید AES موقتی** تولید می‌شود.
2. فایل با استفاده از **AES-256-GCM** رمزگذاری می‌شود.
3. **کلید AES** با استفاده از کلید عمومی RSA مقصد رمزگذاری می‌شود.
4. داده‌ها و متادیتا امضا می‌شوند تا از صحت و یکپارچگی آن‌ها اطمینان حاصل شود.

در ادامه، مراحل کد به صورت جزئی توضیح داده می‌شوند:

---

### ۱. بارگذاری و بررسی کلیدها

#### **در متد `__init__`**
- دو کلید RSA از فایل‌های مربوطه بارگذاری می‌شوند:
  1. **کلید خصوصی محلی (برای امضا کردن)**: این کلید برای امضای داده‌ها و متادیتا استفاده می‌شود.
  2. **کلید عمومی مقصد (برای رمزگذاری کلید AES)**: این کلید عمومی برای رمزگذاری کلید AES استفاده می‌شود.

#### **متدهای `_load_and_validate_private_key` و `_load_and_validate_public_key`**
- این متدها فایل کلید را می‌خوانند و بررسی می‌کنند که آیا نوع و اندازه کلید صحیح است یا خیر:
  - اندازه کلید RSA باید حداقل 2048 بیت باشد.
  - کلید خصوصی برای امضا و کلید عمومی برای رمزگذاری استفاده می‌شود.

---

### ۲. عملیات رمزگذاری فایل

#### **متد `encrypt_file`**
این متد اصلی عملیات رمزگذاری را انجام می‌دهد و شامل چندین مرحله است:

##### **مرحله ۱: تولید کلید AES و IV موقت**
- **کلید AES:** یک کلید تصادفی ۳۲ بایتی (۲۵۶ بیت) برای رمزگذاری تولید می‌شود.
- **IV (Initialization Vector):** یک بردار مقداردهی اولیه ۱۲ بایتی تولید می‌شود که برای AES-GCM ضروری است.

##### **مرحله ۲: رمزگذاری کلید AES با کلید عمومی RSA**
- متد `_encrypt_aes_key_with_rsa` کلید AES را با استفاده از کلید عمومی RSA رمزگذاری می‌کند.
- این فرآیند باعث می‌شود کلید AES به‌صورت امن برای مقصد ارسال شود.

##### **مرحله ۳: رمزگذاری فایل با AES-256-GCM**
- فایل ورودی به صورت تکه‌تکه (chunked) خوانده می‌شود تا از استفاده بهینه از حافظه اطمینان حاصل شود.
- محتوای فایل با استفاده از AES-256-GCM رمزگذاری شده و در فایل خروجی نوشته می‌شود.
- در انتهای فایل، **Tag** امنیتی GCM ذخیره می‌شود.

##### **مرحله ۴: تولید امضای فایل**
- متد `_generate_file_signature` هَش (hash) فایل رمزگذاری‌شده به‌همراه IV و Tag را محاسبه کرده و آن را با کلید خصوصی RSA امضا می‌کند.
- این امضا تضمین می‌کند که فایل دست‌کاری نشده است.

##### **مرحله ۵: ساخت متادیتا**
- متادیتا شامل اطلاعاتی مانند:
  - کلید AES رمزگذاری‌شده (به صورت Base64)
  - IV و Tag
  - امضای فایل
  - اطلاعات مربوط به الگوریتم‌های رمزنگاری استفاده‌شده
- متادیتا به فایل JSON نوشته می‌شود.

##### **مرحله ۶: امضای متادیتا**
- متادیتا به صورت جداگانه با کلید خصوصی RSA امضا می‌شود و امضا به متادیتا اضافه می‌شود.

##### **مرحله ۷: ذخیره فایل رمزگذاری‌شده**
- فایل رمزگذاری‌شده به محل خروجی منتقل می‌شود.
- متادیتا در یک فایل جداگانه ذخیره می‌شود.

---

### ۳. جزئیات رمزگذاری کلید AES

#### **متد `_encrypt_aes_key_with_rsa`**
- کلید AES با استفاده از الگوریتم RSA و روش **OAEP** (Optimal Asymmetric Encryption Padding) رمزگذاری می‌شود.
- این روش امن‌ترین روش برای رمزگذاری کلیدها است و از هش SHA-256 برای امنیت بیشتر استفاده می‌کند.

---

### ۴. رمزگذاری محتوا با AES-256-GCM

#### **متد `_encrypt_to_temp_file`**
- این متد فایل ورودی را به صورت تکه‌تکه می‌خواند و هر بخش را رمزگذاری می‌کند.
- IV در ابتدای فایل رمزگذاری‌شده نوشته می‌شود.
- **Tag امنیتی GCM** در انتهای فایل ذخیره می‌شود.
- این Tag برای تأیید صحت و یکپارچگی داده‌ها در فرآیند رمزگشایی استفاده خواهد شد.

---

### ۵. تولید امضاها

#### **امضای فایل**
- متد `_generate_file_signature` یک هَش از داده‌های زیر ایجاد می‌کند:
  1. IV
  2. محتوای فایل رمزگذاری‌شده
  3. Tag
- سپس این هَش با کلید خصوصی RSA امضا می‌شود.

#### **امضای متادیتا**
- متادیتا (به‌جز امضای خودش) به صورت مرتب‌شده به JSON تبدیل می‌شود.
- این داده با کلید خصوصی RSA امضا می‌شود تا تغییرات غیرمجاز قابل تشخیص باشند.

---

### ۶. ساخت متادیتا

#### **متد `_create_metadata`**
- متادیتا شامل اطلاعات زیر است:
  1. کلید AES رمزگذاری‌شده (Base64)
  2. IV (Base64)
  3. Tag (Base64)
  4. امضای فایل (Base64)
  5. تاریخ ایجاد
  6. الگوریتم‌های رمزنگاری استفاده‌شده (AES-256-GCM، RSA-OAEP)

---

### ۷. ویژگی‌های امنیتی

این سیستم امنیت فایل‌ها را به روش‌های زیر تضمین می‌کند:
1. **محرمانگی:** فایل با AES-256 رمزگذاری می‌شود و کلید AES به‌صورت امن با RSA رمزگذاری می‌شود.
2. **یکپارچگی:** فایل و متادیتا با استفاده از RSA امضا می‌شوند.
3. **مقاومت در برابر حملات:** استفاده از GCM (برای AES) و OAEP (برای RSA) امنیت بالایی ارائه می‌دهد.

---

### ۸. کاربرد در دنیای واقعی

این کد برای رمزگذاری امن فایل‌های حساس (مانند داده‌های مالی یا اطلاعات شخصی) در سیستمی که نیاز به انتقال امن و تأیید اعتبار داده‌ها دارد، بسیار مناسب است.






راهنمای فارسی رمزگشا:
### توضیح گام به گام کد به زبان ساده (فارسی):

این کد یک سیستم **رمزگشایی فایل** را پیاده‌سازی می‌کند که از الگوریتم‌های پیشرفته مانند **AES-256-GCM** و **RSA** استفاده می‌کند. این سیستم برای **رمزگشایی امن فایل‌ها** طراحی شده است که شامل بررسی صحت و اعتبار داده‌ها نیز می‌شود. در ادامه، مراحل اجرای این کد را به صورت ساده توضیح می‌دهیم:

---

#### ۱. **بارگذاری کلیدهای RSA**
در متد `__init__`:
- **کلید عمومی امضاکننده** (برای بررسی امضاها) و **کلید خصوصی محلی** (برای رمزگشایی کلید AES) از فایل‌ها بارگذاری می‌شوند.
- متدهای `_load_and_validate_public_key` و `_load_and_validate_private_key`:
  - فایل‌های PEM (که حاوی کلیدهای RSA هستند) را می‌خوانند.
  - بررسی می‌کنند که آیا این کلیدها معتبر هستند (مثلاً نوع آن‌ها و اندازه بیت).

---

#### ۲. **مرحله اصلی رمزگشایی (متد `decrypt_file`)**

این متد اصلی عملیات رمزگشایی را در ۴ گام انجام می‌دهد:

##### **گام ۱: بارگذاری و تأیید متادیتا**
- فایل متادیتا (یک فایل JSON) از مسیر مشخص شده خوانده می‌شود.
- بررسی می‌شود که آیا تمام فیلدهای ضروری (مانند `encrypted_aes_key`, `iv`, `tag`, `file_signature`, `metadata_signature`) موجود هستند.
- متد `_verify_metadata_signature` بررسی می‌کند که امضای دیجیتال متادیتا معتبر است یا نه. این کار با استفاده از کلید عمومی RSA امضاکننده انجام می‌شود.

##### **گام ۲: تأیید امضای فایل رمزگذاری‌شده**
- متد `_verify_file_signature` صحت امضای فایل رمزگذاری‌شده را بررسی می‌کند.
  - ابتدا فایل رمزگذاری‌شده خوانده می‌شود.
  - هَش (hash) فایل، به‌همراه IV و tag، محاسبه می‌شود.
  - سپس این هَش با امضای ذخیره‌شده در متادیتا مقایسه می‌شود.

##### **گام ۳: رمزگشایی کلید AES**
- متد `_decrypt_aes_key` کلید AES رمزگذاری‌شده را از متادیتا می‌گیرد و آن را با کلید خصوصی محلی RSA رمزگشایی می‌کند.
- این کلید AES برای رمزگشایی محتوای فایل استفاده خواهد شد.

##### **گام ۴: رمزگشایی محتوای فایل**
- متد `_decrypt_file_content` فایل رمزگذاری‌شده را با استفاده از کلید AES رمزگشایی می‌کند.
  - ابتدا IV و tag از متادیتا یا فایل خوانده می‌شود.
  - سپس محتوای رمزگذاری‌شده فایل (ciphertext) با استفاده از AES-256-GCM رمزگشایی می‌شود.
  - در نهایت، محتوای رمزگشایی‌شده در مسیر خروجی ذخیره می‌شود.

---

#### ۳. **جزئیات کلیدها و امضاها**

- **کلید AES (رمزگشایی داده‌ها):**
  - کلید AES به صورت تصادفی (random) در زمان رمزگذاری تولید شده است.
  - این کلید با استفاده از RSA رمزگذاری شده و در متادیتا ذخیره شده است.

- **کلیدهای RSA (امضا و رمزگشایی کلید AES):**
  - کلید عمومی RSA برای تأیید امضاها استفاده می‌شود.
  - کلید خصوصی RSA برای رمزگشایی کلید AES استفاده می‌شود.

- **امضای فایل و متادیتا:**
  - امضای متادیتا و فایل تضمین می‌کنند که داده‌ها دست‌کاری نشده‌اند و از منبع معتبر هستند.

---

#### ۴. **نکات امنیتی**
- **صحت‌سنجی داده‌ها:** با استفاده از امضای دیجیتال RSA، هرگونه تغییر در متادیتا یا فایل رمزگذاری‌شده تشخیص داده می‌شود.
- **رمزنگاری امن:** کلید AES با استفاده از RSA رمزگذاری شده و تنها با کلید خصوصی RSA قابل رمزگشایی است.
- **پاک‌سازی امن:** در صورت بروز خطا، فایل‌های خروجی ناقص حذف می‌شوند.

---

### خلاصه عملیات:
1. کلیدهای RSA بارگذاری و بررسی می‌شوند.
2. متادیتا خوانده شده و امضای آن بررسی می‌شود.
3. کلید AES از متادیتا رمزگشایی می‌شود.
4. فایل رمزگذاری‌شده با استفاده از AES رمزگشایی و ذخیره می‌شود.

---

### کاربرد در دنیای واقعی:
این نوع رمزگشایی برای انتقال ایمن فایل‌های حساس (مانند اسناد مالی یا داده‌های پزشکی) در سیستم‌هایی که نیاز به حفظ محرمانگی، صحت و اعتبار داده‌ها دارند، استفاده می‌شود.


# Secure File Encryptor with ZIP

## Overview
This script encrypts a file and stores it in a password-protected ZIP archive using AES-256 encryption. The encryption password is securely read from a `.env` file, ensuring automation and security.

## Features
- AES-256 encrypted ZIP file creation
- Secure password retrieval from a `.env` file
- Automatic cleanup of temporary files
- Strong error handling and logging

## Prerequisites
Ensure you have the following installed:
- Python 3.7+
- Required Python packages:
  ```sh
  pip install pyzipper python-dotenv
  ```

## Installation
1. Clone or download the script.
2. Ensure the `.env` file is correctly set up (see below).

## Usage
### Step 1: Create a `.env` File
Create a `.env` file in a secure location and add:
```env
ENCRYPTION_PASSWORD="yourstrongpassword1234"
```
Ensure the password is at least 16 characters long for security.

### Step 2: Run the Script
Use the following command to encrypt a file:
```sh
python script.py --input_file test.txt --env_file /path/to/.env
```

### Arguments:
- `--input_file` : Path to the file you want to encrypt.
- `--env_file` : Path to the `.env` file containing the encryption password.

### Example
```sh
python enc.py --input_file test.txt --env_file ~/.env
```

## Output
- Encrypted ZIP file: `test.txt.zip`
- Password-protected with AES-256 encryption

## Security Considerations
- Keep your `.env` file in a secure location.
- Do not share the password or ZIP file openly.
- Ensure temporary files are securely deleted (handled by the script).

## Troubleshooting
### "Failed to create encrypted zip"
Check the following:
- Ensure the `.env` file exists and contains a valid password.
- Verify write permissions for the output directory.
- Ensure `pyzipper` and `django-environ` are installed.

### "Password must be at least 16 characters long"
- Update the `.env` file with a longer, stronger password.

## License
MIT License. Feel free to modify and improve!

## Author
Aslani / Fardaad

