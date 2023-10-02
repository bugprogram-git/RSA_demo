# 整体架构
* 1.客户端连接服务端
* 2.服务端发送公钥的长度和公钥其中公钥的长度位固定4个字节，类型位整形(int)
* 3.客户端使用服务端的公钥加密一段信息，发送固定为整形4字节加密信息长度，以及加密的信息
* 4.上述的信息作为AES的密钥，服务端使用这个密钥进行扩展，扩展成一个128位的AES密钥
* 5.服务端获取到AES密钥后，服务端将secret使用这个AES密钥进行加密，发送给客户端