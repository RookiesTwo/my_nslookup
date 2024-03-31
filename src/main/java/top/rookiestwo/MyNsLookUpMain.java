package top.rookiestwo;

import org.pcap4j.core.*;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.MacAddress;

import java.io.EOFException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedList;
import java.util.concurrent.TimeoutException;

public class MyNsLookUpMain {

    public static void main(String[] args) throws PcapNativeException, UnknownHostException, NotOpenException, EOFException, TimeoutException {

        String domainName="wheatserver.top";
        byte[] domainBytes=domainName.getBytes(StandardCharsets.US_ASCII);
        for (byte b : domainBytes) {
            System.out.printf("%02X ", b);
        }
        System.out.println();

        int portTry=49152;
        while(!isPortAvailable(portTry)){
            portTry++;
        }
        System.out.println(portTry);
        //以字节数组形式构建hostPort
        byte[] hostPort=new byte[2];
        hostPort[0] = (byte) ((portTry >> 8) & 0xFF);
        hostPort[1] = (byte) (portTry & 0xFF);
        for (byte b : hostPort) {
            System.out.printf("%02X ", b);
        }
        System.out.println();
        //本机IP为：
        InetAddress addr = InetAddress.getByName("10.29.146.170");
        String ipToCapture="1.1.1.1";
        PcapNetworkInterface nif = Pcaps.getDevByAddress(addr);
        int snapLen = 65536;
        PcapNetworkInterface.PromiscuousMode mode = PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;
        //监听超时时间5000ms
        int timeout = 5000;
        PcapHandle handle = nif.openLive(snapLen, mode, timeout);
        //根据bpfExpression来过滤数据包，此处只获取跟1.1.1.1有关的数据包
        handle.setFilter("ip dst "+ipToCapture,BpfProgram.BpfCompileMode.OPTIMIZE);
        //getNextPacketEx为等待下一个包到来，会阻塞线程
        Packet packet = handle.getNextPacketEx();
        handle.close();
        IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
        Inet4Address srcAddr = ipV4Packet.getHeader().getSrcAddr();
        Inet4Address dstAddr = ipV4Packet.getHeader().getDstAddr();
        System.out.println(srcAddr);
        System.out.println(dstAddr);
        System.out.println(packet);
    }

    //本机网卡MAC：84:7b:57:c5:ac:b0
    MacAddress hostMAC=MacAddress.getByName("84:7b:57:c5:ac:b0");
    //网关MAC：10-4f-58-6c-0c-00
    MacAddress gatewayMAC=MacAddress.getByName("10-4f-58-6c-0c-00");

    //为了解决开发最大困难-发包和包的构筑临时用的方法
    public void BuildAndSendPacket(){
        //构建以太网header

        //依照老师的要求，手搓数据包，第一步，获取MAC字节码
        byte[] hostBytes=hostMAC.getAddress();
        byte[] gatewayBytes=gatewayMAC.getAddress();
        //由于是ipv4
        byte[] etherType={(byte)0x08,(byte)0x00};

        //手搓ip数据包包头
        byte versionAndHeaderLength = (byte) 0x45; // 版本和头部长度
        byte serviceType = (byte) 0x00; // 服务类型
        short totalLength; // 总长度，后边根据内容定
        short identification = (short) 0x0000; // 标识
        short flagsAndFragmentOffset = (short) 0x0000; // 标志和片偏移
        byte ttl = (byte) 0x80; // TTL,设定为128次
        byte protocol = (byte) 0x11; // 协议,UDP为17,即0x11
        short ipChecksum = (short) 0x0000; // 校验和,不需要，设置为0


        //手搓UDP头部
        //从49152开始寻找可用端口直到找到
        int portTry=49152;
        while(!isPortAvailable(portTry)){
            portTry++;
        }
        //以字节数组形式构建hostPort
        byte[] hostPort=_2ByteArrayBuild(portTry);

        //由于专用于查询dns，目标端口永远是53。硬编码？启动！
        byte[] dstPort=_2ByteArrayBuild(53);

        byte length = 20; // UDP数据包长度，包括UDP头部和数据部分
        byte udpChecksum = 0x00; // 校验和，设置为0

        //构建dns请求头部
        short transactionID=0x000a;//事务ID
        short flags=0x0100;//标志位
        short questions=0x0001;//问题数
        short answerRRs=0x0000;//回答数
        short authorityRRs=0x0000;//权威回答数
        short additionalRRs=0x0000;//额外回答数

        //构建dns请求报文
        String domainName="wheatserver.top";
        byte[] domainBytes=domainName.getBytes();

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
    public byte[] domainToBytes(String inputDomain){
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
}