# Readme
This repository contains code and documentation related to the paper:
```
"SARA: Secure Android Remote Authorization"
Abdullah Imran, Habiba Farrukh, Muhammad Ibrahim, Z. Berkay Celik, and Antonio Bianchi
```
published at the `Usenix Security Symposium`, 2022.\
\
The code is released as an Android library that can be integrated in any existing Android app.\
The documentation is available in this [PDF](https://github.com/purseclab/SARA-Secure-Android-Remote-Authorization/blob/master/SARA%20Documentation.pdf) file.\
ProVerif code is available in this [folder](https://github.com/purseclab/SARA-Secure-Android-Remote-Authorization/tree/master/ProVerifProofs).\
The original paper is available [here](https://www.usenix.org/conference/usenixsecurity22/presentation/imran).

#### Fixes
After the publication of this paper, we were notified by `Prof. XiangHang Mi` from `University of Science and Technology of China` that our original implementation could potentially be bypassed by a root attacker.
As a countermeasure, we updated the code to use the `setUserAuthenticationParameters` API, available in modern Android devices, as explained in the original paper in `Section 4.4`.
