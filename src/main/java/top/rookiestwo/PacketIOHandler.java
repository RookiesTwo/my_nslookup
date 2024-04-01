package top.rookiestwo;

import org.pcap4j.core.*;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;

import java.io.EOFException;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.concurrent.*;

public class PacketIOHandler {

    public void runDNSRequest(String targetDomain){
        ExecutorService executor= Executors.newFixedThreadPool(2);
        //开一个线程发包
        executor.submit(()->{
            try {
                buildAndSendDNSRequest(targetDomain);
            } catch (PcapNativeException | SocketException | UnknownHostException | NotOpenException e) {
                throw new RuntimeException(e);
            }
        });
        Future<Packet> packetInfo=executor.submit(this::listenForDNSResponse);
        System.out.println(packetInfo);
    }

    //监听下一个与usingDNS的IP地址有关的数据包
    //此方法不应在主线程中执行
    private Packet listenForDNSResponse() throws PcapNativeException, NotOpenException, EOFException, TimeoutException {
        PcapNetworkInterface nif = Pcaps.getDevByAddress(MyNsLookUpMain.hostIP);
        int snapLen = 65536;
        PcapNetworkInterface.PromiscuousMode mode = PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;
        //监听超时时间5000ms
        PcapHandle handle = nif.openLive(snapLen, mode, MyNsLookUpMain.timeoutTime);
        //根据bpfExpression来过滤数据包，此处只获取跟指定DNS有关的数据包
        handle.setFilter("ip dst "+MyNsLookUpMain.usingDNS.getHostAddress(),BpfProgram.BpfCompileMode.OPTIMIZE);
        //getNextPacketEx为等待下一个包到来，会阻塞线程
        Packet packet = handle.getNextPacketEx();
        handle.close();

        IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);

        return ipV4Packet;
        /*Inet4Address srcAddr = ipV4Packet.getHeader().getSrcAddr();
        Inet4Address dstAddr = ipV4Packet.getHeader().getDstAddr();
        System.out.println(srcAddr);
        System.out.println(dstAddr);
        System.out.println(packet);*/
    }

    //构建并发送查询指定域名的IP的数据包
    //此方法最好不要在主线程运行
    private void buildAndSendDNSRequest(String domain) throws PcapNativeException, SocketException, UnknownHostException, NotOpenException {
        PcapNetworkInterface nif = Pcaps.getDevByAddress(MyNsLookUpMain.hostIP);
        int snapLen = 65536;
        PcapNetworkInterface.PromiscuousMode mode = PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;
        //监听超时时间5000ms
        PcapHandle handle = nif.openLive(snapLen, mode, MyNsLookUpMain.timeoutTime);
        //构建数据包并发送
        MyNsLookUpMain.requestTimes++;
        DNSPacketBuilder dnsBuilder=new DNSPacketBuilder();
        byte[] bytePacket=dnsBuilder.build("wheatserver.top", MyNsLookUpMain.usingDNS.getHostAddress());
        System.out.println("正在发送数据包：");
        for (byte b : bytePacket) {
            System.out.printf("%02X ", b);
        }
        System.out.println();
        handle.sendPacket(bytePacket);
        handle.close();
    }
}
