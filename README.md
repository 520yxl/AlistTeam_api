# AlistTeam_api
## 阿里云盘：
##### 在config.json配置文件中填入对应的开放平台应用的APP ID和APP Secret，drive_id可空，scope授权范围（根据你的应用可选的授权权限进行填写，默认是全部授权范围）
##### redirect_uri地址是：你的域名+/alipan-callback
#### 使用refresh_token更新接口
##### json格式post请求

| 参数名| -|
|--------|--------|
| client_id| 必填|
| client_secret|  必填|
| drive_id| 可选|
| refresh_token| 必填|
---
## OneDrive：
##### 在config.json配置文件中填入填入对应的开放平台应用的客户端id和客户端密码，scope授权范围（根据你的应用已有的授权权限进行填写，默认是:Files.ReadWrite.All,offline_access）
##### redirect_uri地址是：你的域名+/onedrive-callback
#### 使用refresh_token更新接口
##### json格式post请求

| 参数名| -|
|--------|--------|
| client_id| 必填|
| client_secret|  必填|
| refresh_token| 必填|
