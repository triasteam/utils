### 使用方法：
1. 配置server,  找到 ${user.home}/.m2/settings.xml。${user.home}/.m2是mvn 默认仓库地址，如果该路径下没有settings.xml可以从${MAVEN_HOME}/config目录copy一份过来。或者直接修改${MAVEN_HOME}/config/settings.xml。
    ```
    <servers>
        <server>
            <id>github</id>
            <username>github_login_name</username>
            <password>github_login_password</password>
        </server>
    </servers>
    ```
    这里，需要给username添加maven代码仓库的管理员权限。
2. clone工程到本地
    ```
    :~$ git clone https://github.com/triasteam/utils.git
    ```
3. 部署并上传jar
    ```
    :~$ cd utils/crypto
    :~/utils/crypto$ mvn clean deploy
    ```

 4. 常见问题：
  - target/classes not found
    如果工程没有download到登陆用户目录，需要给登陆用户工程目录的读写权限。
    
