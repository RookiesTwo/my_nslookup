package top.rookiestwo;

import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

import java.net.InetAddress;

public class MyNsLookUpMain {
    public static void main(String[] args) {
        System.out.println("Hello world!");
        InetAddress addr = InetAddress.getByName("192.168.10.100");
        PcapNetworkInterface nif = Pcaps.getDevByAddress(addr);
    }
}