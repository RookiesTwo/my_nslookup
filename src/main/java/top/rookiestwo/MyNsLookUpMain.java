package top.rookiestwo;

import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

import java.net.InetAddress;
import java.net.UnknownHostException;

public class MyNsLookUpMain {
    public static void main(String[] args) throws UnknownHostException, PcapNativeException {
        System.out.println("Hello world!");
        InetAddress addr = InetAddress.getByName("192.168.10.100");
        PcapNetworkInterface nif = Pcaps.getDevByAddress(addr);
    }
}