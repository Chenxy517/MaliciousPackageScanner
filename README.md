# MaliciousPackageScanner
## Introduction
The rise of supply chain attacks in recent years presents a significant and challenging cybersecurity issue that requires attention and needs to be addressed. Protecting the integrity of open source is crucial to the culture of trust on which current technological innovation depends. Moreover, two of the most popular package managers, PIP and NPM, have been actively targeted as conduits for malicious code, making them increasingly vulnerable to attacks. PIP is a package manager for Python packages, aiding in installation, upgrades, and managing third-party libraries or modules that extend the functionality of Python. It is the standard package manager for Python and is used to install packages from a wide variety of sources. NPM is a package manager for JavaScript packages, with the same functionality as PIP except it is used for Node.js packages instead. Both are essential tools for developers to manage dependencies and packages for projects, as well as allow developers to publish their own packages to share with the greater community, making it easier for others to use and contribute to their work. As such, it is evident why malicious attacks on both managers can create a variety of issues. Our project thus aims to mitigate these risks by creating a scanner, which consists of two main functions, that can quickly identify any potential risks, focusing on metadata checking as well as source code analysis of packages downloaded from PIP and NPM repositories. Our metadata checking function verifies the email address of the uploader for a specific package, and our source code analysis function scans the package and reports any pattern matches that correlate to potentially malicious code. We hope that our scanner will not only protect developers from potentially harmful packages, but also provide further knowledge on methodologies that users can use to further protect themselves from falling into any major pitfalls that arise from malicious attacks.
## Structure Overview
From a high level of perspective, our project consists of two building blocks. The first part functions as metadata checking, which focuses on the legality of the email address of the package information. This function can report missing email address, fake email domain, re-registered email address and breached email account. The other part looks at the source code of the package. Given a directory containing a pypi/npm package, our implementation will compare every line of every file within that directory against a list of rules which may point to potentially malicious behavior.  The rules that were triggered along with a brief description is given to the user upon every scan.  
Apart from these two main functions, we also built interfaces to download package information and source code according to PYPI and NPM packages.
## Run
```shell
git clone https://github.com/Chenxy517/MaliciousPackageScanner.git
cd MaliciousPackageScanner
python scanner.py
```
## Evaluation
### Email
For the evaluation of email checking function, we weren’t be able to do large scale tests because haveIbeenpwnd api only allows 10 requests per minutes. But we manually test the function with over 500  PYPI packages. The whole name list(packages_name.txt) is contained in the GitHub repository. There are over 450000 PYPI packages so far. With the 500 sample packages we test, we found 6 packages have issues missing email. In this case, this does not necessarily promise that this package is under attack. But users have to be careful about this, because maintainer is unlikely to keep this library updated. Another 13 packages have been judges as having email with expired or illegal domain. Such packages are exposed to a higher risk of being compromised, since hackers can take control of the email account. 8 packages’ emails have been found in multiple data breaches, which also have the crisis of being compromised. 

According to the 500 sample packages, we totally found 27 suspicious packages that may be attacked by hackers. But unfortunately we could not find any already malicious package that should be reported. So we can say that the alarm mechanism against malicious PYPI packages is quite mature and they get reported soon after being released. But there are still some packages that are under risks of being compromised, our email checking function can flag them out and users should always be careful when importing these libraries.
### Source Code
For the source code part, we randomly tested 500 PyPI packages. According to our scanner, 28 were marked as 28 have been flagged with security warnings. Here are the number of the appeared warnings:XOR-encoded strings rule(11 times)；requests to download binary rule(11 times)；Make remote binary executable(1 time)；Use of os.popen rule(3 times)；Use of subprocess with PIPE rule(2 times)；Browser password theft rule(2 times)；Keylogger pattern rule(1 time)；Access to clipboard data rule(1 time).
The warnings indicate that certain files within the packages have code that could potentially be used to carry out malicious activities, such as stealing passwords or downloading remote binaries. In addition, some of the files contain XOR-encoded strings, which could indicate an attempt at code obfuscation.
Two of the packages, pyfakefs and scslabs2, have multiple files that have been flagged with potential malware. For example, fake_filesystem_shutil_test.py and fake_os_test.py in pyfakefs have been flagged for using chmod or os.chmod to make a remote binary executable, while serializer.py in scslabs2 has been flagged for containing XOR-encoded strings. However, after careful review, we did not mark them as malicious packages because the description of these projects may have triggered our flags. It is important to take these warnings seriously and to investigate them further, as they could potentially indicate that the packages are compromised or contain malicious code.
## Contributors
Xingyu Chen

Siyuan Zhang

Noam Metivier

Jason Wang

Luke Bacopoulos
