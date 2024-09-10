### Project Overview: Web-Application-Security-Assessment-with-Zed-Attack-Proxy-ZAP
This project involved performing security assessments on a web application.
The target web app used was Damn Vulnerable Web Application (DVWA). 

The main focus was on identifying vulnerabilities, testing injection attacks, and evaluating authentication mechanisms. 
Below is a detailed breakdown of each process


#### **1. Setting up the Environment**

- **DVWA Installation and Configuration**: The first step involved setting up DVWA on a local server.
-  The application was configured.
  
![1](https://github.com/user-attachments/assets/c2f4f87c-6b5d-48c0-b6be-ba539e93bee4)

- **OWASP ZAP Configuration**: OWASP ZAP was launched on Kali Linux, and the proxy settings were configured.
- The browser was set to route traffic through ZAP's proxy, allowing for interception of HTTP requests.

---

#### **2. Intercepting Traffic**

Once DVWA was launched in the browser, ZAP successfully intercepted all the web traffic between the browser and the application. 
This step was essential for analyzing requests and responses for potential vulnerabilities.

  ![2](https://github.com/user-attachments/assets/6fdf86f8-26bc-47ce-8f2c-ac8bd90c3551)

---

#### **3. Identifying Vulnerabilities**

- **Automated Vulnerability Scanning**: ZAP’s active scanner was run on DVWA to identify security weaknesses.
- The scan results highlighted several vulnerabilities, including SQL injection and cross-site scripting (XSS).

  ![6](https://github.com/user-attachments/assets/686b5188-8c4b-486b-9b35-fce00b6c7ec0)
![5](https://github.com/user-attachments/assets/6669949d-3ef6-41d9-8bcd-f36acecbf3a9)
![4](https://github.com/user-attachments/assets/f6c9a71d-6beb-4d11-816a-488573219abd)



Each identified vulnerability was categorized based on severity, with accompanying recommendations for fixing the issues.
![3](https://github.com/user-attachments/assets/59031bd7-e528-4cb1-bd63-0386b5205ed4)
 
---

#### **4. Testing Injection Attacks**

- **SQL Injection**: SQL injection tests were manually conducted by intercepting requests in ZAP and modifying input fields in DVWA. Queries such as `1' OR '1'='1` were injected, and the application’s responses were analyzed to confirm the vulnerability.
  
 ![SQL ACTIVE SCAN](https://github.com/user-attachments/assets/22292dc1-a2d8-45d8-ad82-97cf5c3168cc)
![SQL](https://github.com/user-attachments/assets/72cd4bde-0154-458b-b28b-fbde707489c9)


- **Cross-Site Scripting (XSS)**: XSS tests were performed by injecting scripts into input fields, and ZAP captured the response. Alerts for detected XSS vulnerabilities were noted.

![CROSS SCRIPT](https://github.com/user-attachments/assets/bee050a4-5693-4196-bef4-21372738590b)


---

#### **5. Evaluating Authentication Mechanisms**

- **Brute Force Attacks**: ZAP’s brute-force tool was used to test DVWA’s login page by attempting dictionary attacks on the authentication system. The login requests were captured, and attempts were made to bypass authentication mechanisms.

  ![AUTHEN](https://github.com/user-attachments/assets/c690ed2f-7baf-48c9-93d7-941980fdef79)



---

#### **6. Reporting Findings**

After completing the security tests, an HTML report was generated using OWASP ZAP. 
The report summarized all the vulnerabilities found during the assessment, providing a detailed analysis of each issue, risk ratings, and recommendations for remediation.

  ![report](https://github.com/user-attachments/assets/a099551d-0463-42e1-a657-8e7528e05359)


---

### Conclusion

This project successfully demonstrated the use of OWASP ZAP to assess the security of a web application. Vulnerabilities such as SQL injection, XSS, and authentication flaws were identified and documented. 
The findings provided insights into how to strengthen the security of DVWA.

[2024-09-10-ZAP-Report-.pdf](https://github.com/user-attachments/files/16944327/2024-09-10-ZAP-Report-.pdf)


