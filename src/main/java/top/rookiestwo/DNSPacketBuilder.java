package top.rookiestwo;

import org.pcap4j.util.MacAddress;

import java.net.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.Random;

public class DNSPacketBuilder {
    //硬编码网关MAC地址，我查了一圈，内网、外网。真的不好获取，可能其他语言好获取吧。
    //网关的MAC让jvm来干是真拿不到。我唯一能想到的办法就是开个进程跑ipconfig指令然后用正则表达式匹配。
    //但是这样写太丑陋了，我觉得还不如硬编码，或者直接让用户输入。
    //反正是北邮内网，还是直接硬编码吧。该MAC仅适用于北京邮电大学内网。
    //本来用java写链路层我就觉得挺抽象的了
    MacAddress gatewayMAC=MacAddress.getByName("22-2b-20-82-fd-1b");
    //10-4f-58-6c-0c-00

    MacAddress hostMAC;
    InetAddress hostIP=null;
    public DNSPacketBuilder() throws UnknownHostException, SocketException {
        //获取本机IP从而获得MAC
        hostIP=InetAddress.getLocalHost();
        NetworkInterface networkInterface = NetworkInterface.getByInetAddress(hostIP);
        hostMAC= MacAddress.getByAddress(networkInterface.getHardwareAddress());
    }
    public byte[] build(String inputDomain,String dnsServerIP) throws UnknownHostException {
        //构建以太网header

        //依照老师的要求，手搓数据包，第一步，获取MAC字节码
        byte[] gatewayBytes=gatewayMAC.getAddress();
        byte[] hostBytes=hostMAC.getAddress();
        //由于是ipv4
        byte[] etherType=_2ByteArrayBuild(0x0800);

        //手搓ip数据包包头
        byte versionAndHeaderLength = (byte) 0x45; // 版本和头部长度
        byte serviceType = (byte) 0x00; // 服务类型
        byte[] totalLength; // 总长度，后边根据内容定

        // 创建一个随机数生成器
        Random random = new Random();

        // 生成一个随机的Identification值（16位）
        int identificationRandom = random.nextInt(65536);
        byte[] identification = _2ByteArrayBuild(identificationRandom); // 标识。由于不需要分片，无所谓
        byte[] flagsAndFragmentOffset = _2ByteArrayBuild(0x0000); // 标志和片偏移
        byte ttl = (byte) 0x80; // TTL,设定为128次
        byte protocol = (byte) 0x11; // 协议,UDP为17,即0x11
        byte[] ipChecksum = _2ByteArrayBuild(0x0000); // 校验和,不需要，设置为0
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

        byte[] length = _2ByteArrayBuild(20); // UDP数据包长度，包括UDP头部和数据部分
        byte[] udpChecksum = _2ByteArrayBuild(0x4cc9); // 校验和，设置为0

        //构建dns请求头部
        byte[] transactionID=_2ByteArrayBuild(0x002f);//事务ID
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
        length=_2ByteArrayBuild(ipLength-20);


        //接下来让所有的连成一片
        ByteBuffer buffer = ByteBuffer.allocate(14+ipLength);
        //以太包头
        buffer.put(gatewayBytes);
        buffer.put(hostBytes);
        buffer.put(etherType);
        //ip包头
        buffer.put(versionAndHeaderLength);
        buffer.put(serviceType);
        buffer.put(totalLength);
        buffer.put(identification);
        buffer.put(flagsAndFragmentOffset);
        buffer.put(ttl);
        buffer.put(protocol);
        buffer.put(ipChecksum);
        buffer.put(srcIP);
        buffer.put(dstIP);
        //udp包头
        buffer.put(hostPort);
        buffer.put(dstPort);
        buffer.put(length);
        buffer.put(udpChecksum);
        //dns头部
        buffer.put(transactionID);
        buffer.put(flags);
        buffer.put(questions);
        buffer.put(answerRRs);
        buffer.put(authorityRRs);
        buffer.put(additionalRRs);
        //dns请求报文
        buffer.put(domainBytes);
        buffer.put(queryType);
        buffer.put(queryClass);


        //ByteBuffer buffer2 = ByteBuffer.allocate(/*dns报头*/12+/*dns报文*/domainBytes.length+4);
        /*buffer2.put(transactionID);
        buffer2.put(flags);
        buffer2.put(questions);
        buffer2.put(answerRRs);
        buffer2.put(authorityRRs);
        buffer2.put(additionalRRs);
        //dns请求报文
        buffer2.put(domainBytes);
        buffer2.put(queryType);
        buffer2.put(queryClass);
        UdpPacket udpPacket = new UdpPacket.Builder()
                .srcAddr(InetAddress.getByName("192.168.137.228"))
                .dstAddr(InetAddress.getByName("1.1.1.1"))
                .srcPort(UdpPort.getInstance((short) 49153))
                .dstPort(UdpPort.getInstance((short) 53))
                .correctChecksumAtBuild(true) // 计算校验和
                .correctLengthAtBuild(true)
                .payloadBuilder(new UnknownPacket.Builder().rawData(buffer2.array()))
                .build();*/
        //return udpPacket.getRawData();
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

    private static InetAddress getGateway(NetworkInterface networkInterface) {
        try {
            // 获取网络接口的所有IP地址
            Enumeration<InetAddress> addresses = networkInterface.getInetAddresses();
            while (addresses.hasMoreElements()) {
                InetAddress address = addresses.nextElement();
                // 检查是否为IPv4地址，并且不是本地链路地址
                if (address instanceof Inet4Address && !address.isSiteLocalAddress()) {
                    return address;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
