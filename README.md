<br>

<div align="center">
  <img src="https://capsule-render.vercel.app/api?type=rounded&height=160&color=gradient&text=Mojtaba%20Reality%20Surgeon%20V7.3&fontAlign=50&fontAlignY=50&fontSize=40" />
  
  <p><b>پایپ‌لاین خودکار جراحی، پالایش، انتخاب و فیلترینگ هوشمند کانفیگ‌های Reality برای اپراتورهای ایران</b></p>
</div>

<div align="center">

[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)]()
[![Update](https://img.shields.io/badge/Update-Every%203%20Hours-blue?style=for-the-badge)]()
[![Python](https://img.shields.io/badge/Python-3.13-aff?style=for-the-badge&logo=python)]()
[![Telemetry](https://img.shields.io/badge/Telemetry-V7.3--Enabled-orange?style=for-the-badge)]()

</div>

<hr>

<div dir="rtl">

## 🧐 این پروژه چیست؟

این پروژه یک سیستم اتوماسیون کامل (Pipeline) است. اسکریپت اختصاصی **The Surgeon V7.3** (جراح) کانفیگ‌های خام را از سورس‌های مختلف جمع‌آوری می‌کند، ترافیک Reality را ایزوله می‌کند، با اعمال فیلترهای سخت‌گیرانه روی پورت‌ها و پارامترها نودهای ضعیف یا ناسازگار را حذف می‌کند، سپس با رتبه‌بندی و انتخاب هوشمند، نودهایی را نگه می‌دارد که بیشترین شانس پایداری و سازگاری روی اینترنت **مخابرات، همراه اول و ایرانسل** را داشته باشند.

این سیستم هر **۳ ساعت یک‌بار** به‌طور خودکار روی GitHub Actions با استفاده از پایتون نسخه **3.13** اجرا شده و لیست نهایی را در فایل `MOJTABA_CLEAN_LIST.txt` به‌روزرسانی می‌کند.

</div>

<br>

<div align="center">
  <h3 style="color: #00D2FF;">🚀 قابلیت‌های کلیدی (Key Features - V7.3)</h3>
  <table dir="rtl" style="margin-left: auto; margin-right: auto; border-radius: 10px; overflow: hidden;">
    <thead>
      <tr style="background-color: #21262d;">
        <th align="center">قابلیت</th>
        <th align="center">عملکرد فنی</th>
        <th align="center">دستاورد برای کاربر</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td align="center"><b>Multi-Layer Deduplication</b></td>
        <td align="center">حذف تکراری‌ها بر اساس ترکیب <code>IP:Port + SNI + PBK</code></td>
        <td align="center">کاهش نودهای تکراری، فیک و کم‌ارزش</td>
      </tr>
      <tr>
        <td align="center"><b>Golden Ports Priority</b></td>
        <td align="center">تمرکز روی پورت‌های 443, 2053, 2083, 8443</td>
        <td align="center">پایداری بهتر روی اینترنت ایران</td>
      </tr>
      <tr>
        <td align="center"><b>Mandatory Fingerprint</b></td>
        <td align="center">اعمال اجباری <code>fp=chrome</code> و <code>type=tcp</code> برای Reality</td>
        <td align="center">شباهت بیشتر به ترافیک واقعی و سازگاری بهتر با کلاینت‌ها</td>
      </tr>
      <tr>
        <td align="center"><b>Operator-Aware Ranking</b></td>
        <td align="center">امتیازدهی بر اساس کیفیت SNI، پورت، ساختار و شانس سازگاری در شبکه ایران</td>
        <td align="center">انتخاب هوشمندتر برای استفاده روزمره</td>
      </tr>
      <tr>
        <td align="center"><b>Strict Reality Filtering</b></td>
        <td align="center">فیلتر دقیق کانفیگ‌ها بر اساس ساختار معتبر و پارامترهای ضروری Reality</td>
        <td align="center">خروجی تمیزتر و usable‌تر</td>
      </tr>
      <tr>
        <td align="center"><b>Failure Telemetry</b></td>
        <td align="center">ثبت آمار استخراج، پذیرش، حذف و نتیجه نهایی در <code>JSON</code></td>
        <td align="center">مانیتورینگ بهتر سلامت کل پایپ‌لاین</td>
      </tr>
      <tr>
        <td align="center"><b>Host Diversity Guard</b></td>
        <td align="center">محدودسازی تعداد خروجی از هر میزبان برای جلوگیری از سلطه یک host</td>
        <td align="center">تنوع بیشتر و ریسک کمتر در لیست نهایی</td>
      </tr>
    </tbody>
  </table>
</div>

<br>

<div dir="rtl">

## 📜 تاریخچه تغییرات

<details open>
<summary><b><font color="#00D2FF">نسخه V7.3 (2026-05-29) - پالایش سخت‌گیرانه و انتخاب هوشمندتر</font></b></summary>
<br>
<ul>
  <li><b>Full Pipeline Refinement:</b> بهبود ساختار کلی پردازش برای انتخاب دقیق‌تر و خروجی تمیزتر.</li>
  <li><b>Strict Reality Filtering:</b> اعمال فیلتر سخت‌گیرانه‌تر روی ساختار و پارامترهای Reality.</li>
  <li><b>Operator-Aware Selection:</b> انتخاب بهتر کانفیگ‌ها با تمرکز بر سازگاری بیشتر در شبکه ایران.</li>
  <li><b>Final Output Tuning:</b> بهینه‌سازی لیست نهایی برای usable بودن بیشتر و نویز کمتر.</li>
  <li><b>Host Diversity:</b> جلوگیری از تکرار بیش از حد کانفیگ‌های وابسته به یک میزبان.</li>
  <li><b>GitHub Actions Refresh:</b> به‌روزرسانی workflow برای اجرا روی <code>ubuntu-latest</code> و پایتون <code>3.13</code>.</li>
  <li><b>3-Hour Smart Update Cycle:</b> تثبیت بروزرسانی منظم هر ۳ ساعت.</li>
  <li><b>Single Clean Output:</b> تمرکز خروجی روی فایل نهایی <code>MOJTABA_CLEAN_LIST.txt</code>.</li>
  <li><b>Bug Fixes:</b> رفع باگ 😄</li>
</ul>
</details>

<details dir="rtl">
<summary><b><font color="#999">نسخه V6.2 (2026-05-29)</font></b></summary>
<br>
<ul>
  <li>بهینه‌سازی جزئی در امتیازدهی و تمیزکاری خروجی برای آماده‌سازی نسخه نهایی.</li>
</ul>
</details>

<details dir="rtl">
<summary><b><font color="#999">نسخه V6.0 (2026-05-29)</font></b></summary>
<br>
<ul>
  <li>آماده‌سازی زیرساخت داخلی برای انتخاب دقیق‌تر کانفیگ‌ها.</li>
</ul>
</details>

<details dir="rtl">
<summary><b><font color="#999">نسخه V5.9.1 (2026-05-28)</font></b></summary>
<br>
<ul>
  <li>بهبودهای میانی روی پایداری پردازش و هماهنگی بهتر با سورس‌های ورودی.</li>
</ul>
</details>

<details dir="rtl">
<summary><b><font color="#999">نسخه V5.6 (2026-05-28) - ارتقای پایتون و پایداری</font></b></summary>
<br>
<ul>
  <li><b>Python 3.13 Support:</b> بهینه‌سازی کامل کد برای اجرا در نسخه 3.13.</li>
  <li><b>Enhanced Telemetry:</b> ثبت دقیق آمارهای استخراج، فیلترینگ و دلایل رد شدن نودها.</li>
  <li><b>Deterministic Deduplication:</b> الگوریتم بهتر برای انتخاب بهترین نود از بین رکوردهای تکراری.</li>
  <li><b>Clean Tags:</b> پاکسازی و استانداردسازی خودکار نام کانفیگ‌ها.</li>
</ul>
</details>

<details dir="rtl">
<summary><b><font color="#999">تاریخچه نسخه‌های قبلی</font></b></summary>
<br>
<ul>
  <li><b>V5.5:</b> اضافه شدن سیستم Telemetry و ثبت علل خرابی (Failure Reasons).</li>
  <li><b>V5.0:</b> سیستم رتبه‌بندی هوشمند بر اساس اپراتور (Operator-Aware).</li>
  <li><b>V4.5:</b> پیاده‌سازی Stability Gate برای اطمینان از سلامت ساختار Reality.</li>
</ul>
</details>

<br>

## 🔌 لینک سابسکریپشن (Subscription Link)

برای استفاده در کلاینت‌های **Hiddify**, **V2RayNG**, **Streisand** و... لینک زیر را کپی کنید:

</div>

<div align="center" dir="ltr">
```https

https://raw.githubusercontent.com/Mojtaba1423/My-Clean-Configs/main/MOJTABA_CLEAN_LIST.txt
