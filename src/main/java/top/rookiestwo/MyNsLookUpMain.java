package top.rookiestwo;

import org.pcap4j.core.*;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.MacAddress;

import java.io.EOFException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.concurrent.TimeoutException;

public class MyNsLookUpMain {

    //本机网卡MAC：84:7b:57:c5:ac:b0
    MacAddress hostMAC=MacAddress.getByName("84:7b:57:c5:ac:b0");
    //网关MAC：10-4f-58-6c-0c-00
    MacAddress gatewayMAC=MacAddress.getByName("10-4f-58-6c-0c-00");

    String hostIP="10.29.146.170";

    public static void main(String[] args) throws PcapNativeException, NotOpenException, TimeoutException, UnknownHostException, SocketException, EOFException {

        /*String domainName="wheatserver.top";
        byte[] domainBytes=domainToBytes(domainName);
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
        System.out.println();*/

        //测试
        //本机IP为：
        InetAddress addr = InetAddress.getByName("192.168.137.228");
        String ipToCapture="1.1.1.1";
        PcapNetworkInterface nif = Pcaps.getDevByAddress(addr);
        int snapLen = 65536;
        PcapNetworkInterface.PromiscuousMode mode = PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;
        //监听超时时间5000ms
        int timeout = 5000;
        PcapHandle handle = nif.openLive(snapLen, mode, timeout);

        //构建数据包并发送
        DNSPacketBuilder dnsBuilder=new DNSPacketBuilder();
        byte[] bytePacket=dnsBuilder.build("wheatserver.top", "1.1.1.1");
        for (byte b : bytePacket) {
            System.out.printf("%02X ", b);
        }
        System.out.println();
        handle.sendPacket(bytePacket);



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

    //为了解决开发最大困难-发包和包的构筑临时用的方法

}