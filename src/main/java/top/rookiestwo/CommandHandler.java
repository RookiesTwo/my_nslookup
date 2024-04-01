package top.rookiestwo;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

public class CommandHandler {
    private final Pattern ipPattern = Pattern.compile("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$");

    //此类的方法应当只在主线程执行
    public void run(String command) {
        if (command.startsWith("server ")) {
            String ip = command.substring(7);
            if (isValidIp(ip)) {
                setDnsServer(ip);
            } else {
                System.out.println("Invalid IP address format.");
            }
        } else if (command.matches("^[a-zA-Z0-9.\\-]+$")) {
            sendDNSRequest(command);
        } else if (command.equalsIgnoreCase("exit")) {
            MyNsLookUpMain.close();//关闭进程
        } else {
            System.out.println("Invalid command");
        }
    }
    private void setDnsServer(String targetServer) {
        try{
            MyNsLookUpMain.usingDNS= InetAddress.getByName(targetServer);
        }
        catch (UnknownHostException e){
            System.out.println("输入的IP地址为无效地址.");
        }
    }

    private void sendDNSRequest(String targetDomain){
        MyNsLookUpMain.PacketHandler.runDNSRequest(targetDomain);
    }

    private boolean isValidIp(String ip) {
        Matcher matcher = ipPattern.matcher(ip);
        return matcher.matches();
    }
}
