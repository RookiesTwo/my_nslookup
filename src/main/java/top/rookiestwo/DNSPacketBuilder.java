package top.rookiestwo;

import org.pcap4j.util.MacAddress;

import java.net.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.LinkedList;
import java.util.Random;


public class DNSPacketBuilder {
    MacAddress hostMAC;
    InetAddress hostIP=null;
    public DNSPacketBuilder() throws UnknownHostException, SocketException {
        //获取本机IP从而获得MAC
        hostIP=MyNsLookUpMain.hostIP;
        hostMAC=MyNsLookUpMain.hostMAC;
    }
    public byte[] build(String inputDomain,String dnsServerIP) throws UnknownHostException {
        //依照老师的要求，手搓数据包

        // 第一步，获取MAC字节码
        //构建以太网header
        byte[] gatewayBytes=MyNsLookUpMain.gatewayMAC.getAddress();
        byte[] hostBytes=hostMAC.getAddress();
        //由于是ipv4
        byte[] etherType=_2ByteArrayBuild(0x0800);

        //手搓ip数据包包头
        byte versionAndHeaderLength = (byte) 0x45; // 版本和头部长度
        byte serviceType = (byte) 0x00; // 服务类型
        byte[] totalLength; // 总长度，后边赋值

        // 创建一个随机数生成器
        Random random = new Random();

        // 生成一个随机的Identification值（16位）
        int identificationRandom = random.nextInt(65535);
        byte[] identification = _2ByteArrayBuild(identificationRandom); // 由于不需要分片，具体数值理应无所谓

        byte[] flagsAndFragmentOffset = _2ByteArrayBuild(0x0000); // 标志和片偏移
        byte ttl = (byte) 0x80; // TTL,设定为128次
        byte protocol = (byte) 0x11; // 协议,UDP为17,即0x11
        byte[] ipChecksum = _2ByteArrayBuild(0x0000); // 校验和
        byte[] srcIP= Inet4Address.getByName(hostIP.getHostAddress()).getAddress();//本机IP
        byte[] dstIP=Inet4Address.getByName(dnsServerIP).getAddress();//dns服务器IP

        //手搓UDP头部
        //从49153开始寻找可用端口直到找到
        int portTry=49153;
        while(!isPortAvailable(portTry)){
            portTry++;
        }
        //以字节数组形式构建hostPort
        byte[] hostPort=_2ByteArrayBuild(portTry);

        //由于专用于查询dns，目标端口永远是53。硬编码？启动！
        byte[] dstPort=_2ByteArrayBuild(53);

        byte[] udpLength = _2ByteArrayBuild(20); // UDP数据包长度，包括UDP头部和数据部分
        byte[] udpChecksum = _2ByteArrayBuild(0x0000); // 校验和，初始为0

        //构建dns请求头部
        byte[] transactionID=_2ByteArrayBuild(0x002f+MyNsLookUpMain.requestTimes);//事务ID
        byte[] flags=_2ByteArrayBuild(0x0100);//标志位
        byte[] questions=_2ByteArrayBuild(0x0001);//问题数
        byte[] answerRRs=_2ByteArrayBuild(0x0000);//回答数
        byte[] authorityRRs=_2ByteArrayBuild(0x0000);//权威回答数
        byte[] additionalRRs=_2ByteArrayBuild(0x0000);//额外回答数

        //构建dns请求报文
        byte[] domainBytes=domainToBytes(inputDomain);//域名
        byte[] queryType=_2ByteArrayBuild(0x0001);//dns记录类型，0x0001为A类型
        byte[] queryClass=_2ByteArrayBuild(0x0001);//一般为IN类

        int ipLength=/*ip头*/20+/*udp头*/8+/*dns报头*/12+/*dns报文*/domainBytes.length+4;
        //ip包头的totalLength
        totalLength=_2ByteArrayBuild(ipLength);
        //udp包头的length
        udpLength=_2ByteArrayBuild(ipLength-20);

        //计算IP头和UDP头的checksum值
        ByteBuffer ipHeadBuffer=ByteBuffer.allocate(/*ip头*/20);
        ipHeadBuffer.put(versionAndHeaderLength)
                .put(serviceType).put(totalLength)
                .put(identification)
                .put(flagsAndFragmentOffset)
                .put(ttl)
                .put(protocol)
                .put(ipChecksum)
                .put(srcIP)
                .put(dstIP);

        //udp需要伪首部，比较复杂，但是还好所有数据都列出来了，构建比较方便
        ByteBuffer udpHeadBuffer=ByteBuffer.allocate(/*伪首部*/12+/*udp头*/8+/*dns报头*/12+/*dns报文*/domainBytes.length+4);
        //伪首部
        udpHeadBuffer.put(srcIP)
                .put(dstIP)
                .put((byte)0x00)//全零占位
                .put((byte)0x11)//udp协议编号17
                .put(_2ByteArrayBuild(ipLength-20));//udp实际报文和头部的长度和
        //udp包头
        udpHeadBuffer.put(hostPort)
                .put(dstPort)
                .put(udpLength)
                .put(udpChecksum);//该值目前为0
        //udp报文，即payload
        udpHeadBuffer.put(transactionID)
                .put(flags)
                .put(questions)
                .put(answerRRs)
                .put(authorityRRs)
                .put(additionalRRs)
                .put(domainBytes)
                .put(queryType)
                .put(queryClass);

        //获取两个包头的checksum
        ipChecksum=calculateChecksum(ipHeadBuffer.array());
        udpChecksum=calculateChecksum(udpHeadBuffer.array());

        //接下来让所有的信息连成一个字节数组，即数据包
        ByteBuffer buffer = ByteBuffer.allocate(14+ipLength);

        //以太包头
        buffer.put(gatewayBytes)
                .put(hostBytes)
                .put(etherType);

        //ip包头
        buffer.put(versionAndHeaderLength)
                .put(serviceType).put(totalLength)
                .put(identification)
                .put(flagsAndFragmentOffset)
                .put(ttl)
                .put(protocol)
                .put(ipChecksum)
                .put(srcIP)
                .put(dstIP);

        //udp包头
        buffer.put(hostPort)
                .put(dstPort)
                .put(udpLength)
                .put(udpChecksum);

        //dns头部
        buffer.put(transactionID)
                .put(flags)
                .put(questions)
                .put(answerRRs)
                .put(authorityRRs)
                .put(additionalRRs);

        //dns请求报文
        buffer.put(domainBytes)
                .put(queryType)
                .put(queryClass);

        return buffer.array();
    }

    //判断指定端口是否可用
    public static boolean isPortAvailable(int portNumber) {
        if(portNumber>65535||portNumber<0)return false;
        try (ServerSocket serverSocket = new ServerSocket(portNumber)) {
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    //根据输入的int值,将其转为能存入两个字节的字节数组
    public byte[] _2ByteArrayBuild(int input){
        byte[] temp=new byte[2];
        temp[0] = (byte) ((input >> 8) & 0xFF);
        temp[1] = (byte) (input & 0xFF);
        return temp;
    }

    //将域名构建为符合dns报文格式的字节数组
    public static byte[] domainToBytes(String inputDomain){
        //先将域名拆分为各个部分
        String[] parts = inputDomain.split("\\.");

        LinkedList<Byte> temp=new LinkedList<>();
        //计算每一段的长度，并将每一段的ascii码编码添加到链表temp中
        for(String s:parts){
            temp.add((byte)s.length());
            byte[] stemp=s.getBytes(StandardCharsets.US_ASCII);
            for(byte b:stemp){
                temp.add(b);
            }
        }
        //最后添加结束符
        temp.add((byte)0x00);
        byte[] byteArray = new byte[temp.size()];
        for (int i = 0; i < temp.size(); i++) {
            byteArray[i] = temp.get(i);
        }
        return byteArray;
    }

    //checksum值的计算
    //https://stackoverflow.com/questions/4113890/how-to-calculate-the-internet-checksum-from-a-byte-in-java
    public byte[] calculateChecksum(byte[] inputData) {
        int length = inputData.length;
        int i = 0;
        long sum = 0;
        long data;
        // 处理所有的成对的byte
        while (length > 1) {
            // Corrected to include @Andy's edits and various comments on Stack Overflow
            data = (((inputData[i] << 8) & 0xFF00) | ((inputData[i + 1]) & 0xFF));
            sum += data;
            // 1's complement carry bit correction in 16-bits (detecting sign extension)
            if ((sum & 0xFFFF0000) > 0) {
                sum = sum & 0xFFFF;
                sum += 1;
            }
            i += 2;
            length -= 2;
        }
        // 处理奇数byte的情况
        if (length > 0) {
            sum += (inputData[i] << 8 & 0xFF00);
            // 1's complement carry bit correction in 16-bits (detecting sign extension)
            if ((sum & 0xFFFF0000) > 0) {
                sum = sum & 0xFFFF;
                sum += 1;
            }
        }
        // 反转并取两位
        sum = ~sum;
        sum = sum & 0xFFFF;
        return _2ByteArrayBuild((int)sum);
    }
}
