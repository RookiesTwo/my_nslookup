package top.rookiestwo;

import org.pcap4j.core.*;
import org.pcap4j.packet.DnsPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;

import java.io.EOFException;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeoutException;

public class PacketIOHandler {

    PcapNetworkInterface nif;
    int snapLen = 65536;
    PcapNetworkInterface.PromiscuousMode mode = PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;
    public PacketIOHandler() throws PcapNativeException {
        nif = Pcaps.getDevByAddress(MyNsLookUpMain.hostIP);
    }

    public void runDNSRequest(String targetDomain){
        runDNSRequest(targetDomain,false);
    }
    public void runDNSRequest(String targetDomain,boolean ifPrintReceivePacket) {
        ExecutorService executor= Executors.newFixedThreadPool(2);
        DnsPacket packetInfo;
        //开一个线程发包
        executor.submit(()->{
            try {
                buildAndSendDNSRequest(targetDomain);
            } catch (PcapNativeException | SocketException | UnknownHostException | NotOpenException e) {
                throw new RuntimeException(e);
            }
        });
        try {
            packetInfo=listenForDNSResponse();
            //仅支持A类型和CNAME类型
            packetInfo.getHeader().getAnswers().forEach(record->{
                //偷懒了，直接用pcap4j提供的方法了
                System.out.println("\n\nName:    "+targetDomain);
                System.out.println(record.getDataType());
                System.out.println(record.getRData());
                if(ifPrintReceivePacket){
                    System.out.println("数据包内容:");
                    System.out.println(packetInfo);
                }
            });
        }  catch (TimeoutException e){
            System.out.println("响应超时。");
        } catch( PcapNativeException | NotOpenException | EOFException | IllegalRawDataException e){
            throw new RuntimeException(e);
        }
        //System.out.println(packetInfo);

        executor.shutdown();
    }
    //默认不打印整个数据包



    //监听下一个与usingDNS的IP地址有关的数据包
    //
    private DnsPacket listenForDNSResponse() throws PcapNativeException, NotOpenException, EOFException, TimeoutException, IllegalRawDataException {
        PcapHandle handle = nif.openLive(snapLen, mode, MyNsLookUpMain.timeoutTime);
        //根据bpfExpression来过滤数据包，此处只获取指定DNS发送的数据包
        handle.setFilter("ip src "+MyNsLookUpMain.usingDNS.getHostAddress(),BpfProgram.BpfCompileMode.OPTIMIZE);
        //getNextPacketEx为等待下一个包到来，会阻塞线程
        Packet packet = handle.getNextPacketEx();
        handle.close();

        DnsPacket dnsPacket=packet.get(DnsPacket.class);

        return dnsPacket;
        /*Inet4Address srcAddr = ipV4Packet.getHeader().getSrcAddr();
        Inet4Address dstAddr = ipV4Packet.getHeader().getDstAddr();
        System.out.println(srcAddr);
        System.out.println(dstAddr);
        System.out.println(packet);*/
    }

    //构建并发送查询指定域名的IP的数据包
    //此方法最好不要在主线程运行
    private void buildAndSendDNSRequest(String domain) throws PcapNativeException, SocketException, UnknownHostException, NotOpenException {
        PcapHandle handle = nif.openLive(snapLen, mode, MyNsLookUpMain.timeoutTime);
        //构建数据包并发送
        MyNsLookUpMain.requestTimes++;
        DNSPacketBuilder dnsBuilder=new DNSPacketBuilder();
        byte[] bytePacket=dnsBuilder.build(domain, MyNsLookUpMain.usingDNS.getHostAddress());
        //System.out.println("正在发送数据包：");
        //for (byte b : bytePacket) {
        //    System.out.printf("%02X ", b);
        //}
        System.out.println();
        handle.sendPacket(bytePacket);
        handle.close();
    }
}
