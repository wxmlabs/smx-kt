# SMx Kotlin
[![Build Status](https://travis-ci.org/wxmlabs/smx-kt.svg?branch=master)](https://travis-ci.org/wxmlabs/smx-kt)
[![codecov](https://codecov.io/gh/wxmlabs/smx-kt/branch/master/graph/badge.svg)](https://codecov.io/gh/wxmlabs/smx-kt)

中国国产密码算法的Kotlin实现。

> [BouncyCastle] v1.58 已实现了国产算法。示例代码参见[smx-example-java](/smx-example-java/)。

因为第一次做开源，有很多需要学习。希望开源社区的各位大佬能给予帮助和支持。

联系方式: shiningwang@vshining.com

## 参考文献：

- 《[SM3密码杂凑算法]》


## 目前已实现功能

- 实现SM3核心算法
- 实现名为SMx的java.security.Provider
- 实现SM3算法的MessageDigest


[标准规范]: http://www.oscca.gov.cn/sca/xxgk/bzgf.shtml
[SM3密码杂凑算法]: http://www.sca.gov.cn/sca/xwdt/2010-12/17/1002389/files/302a3ada057c4a73830536d03e683110.pdf
[SM2椭圆曲线公钥密码算法]: http://www.oscca.gov.cn/sca/xxgk/2010-12/17/1002386/files/b791a9f908bb4803875ab6aeeb7b4e03.pdf
[SM2椭圆曲线公钥密码算法推荐曲线参数]: http://www.oscca.gov.cn/sca/xxgk/2010-12/17/1002386/files/b965ce832cc34bc191cb1cde446b860d.pdf
[The SM3 Cryptographic Hash Function]: https://tools.ietf.org/html/draft-oscca-cfrg-sm3-02
[SM2 Digital Signature Algorithm]: https://tools.ietf.org/html/draft-shen-sm2-ecdsa-02

[GmSSL]: https://github.com/guanzhi/GmSSL
[BouncyCastle]: https://github.com/bcgit/bc-java

[《证书认证系统密码及其相关安全技术规范》公告]: http://www.sca.gov.cn/sca/xwdt/2005-06/23/content_bac5968bcbd04d88a2682f8f1e44b5d5.shtml
[证书认证系统密码及其相关安全技术规范]: http://www.sca.gov.cn/sca/xwdt/2005-06/23/bac5968bcbd04d88a2682f8f1e44b5d5/files/bd34a890bdeb4c049ee74a3cfa7d9541.pdf

[国家商用密码算法简介]: https://wenku.baidu.com/view/d2435b1fe518964bcf847cf6.html
[中国商用密码SM4与分组密码应用技术]: https://wenku.baidu.com/view/665bc45c941ea76e59fa0443.html
[国密算法SM1_SM3_SM4的标准数据]: https://wenku.baidu.com/view/a1dd7767650e52ea54189812.html
[SMS4密码算法]: https://wenku.baidu.com/view/db4f7377ac02de80d4d8d15abe23482fb4da027c.html
[加密算法的新发展 基于Pairing的密码技术(SM9算法)研究与应用]: https://wenku.baidu.com/view/da6161023968011ca3009185.html
