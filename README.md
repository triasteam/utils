# utils include util jars below:

### 1. [crypto util](./crypto/README.md)
#### 依赖配置
```
<dependency>
    <groupId>com.iri.utils</groupId>
    <artifactId>utils-crypto</artifactId>
    <version>0.0.1-SNAPSHOT</version>
    <exclusions>
        <exclusion>
            <groupId>org.mockito</groupId>
            <artifactId>mockito-core</artifactId>
        </exclusion>
    </exclusions>
</dependency>
```
     
#### 主要方法
   - 生成base58编码的私钥和地址```EcdsaUtils.generateSecureInfo``` 
     该信息为string格式，可以直接用于存储和传输
   - 直接使用base58编码格式的私钥和地址进行签名```EcdsaUtils.sign```    
   - 直接使用base64编码的签名字符串和base58编码格式的地址进行验签```EcdsaUtils.verifyMessage```    
