package top.rookiestwo;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

public class CommandHandler {
    private final Pattern ipPattern = Pattern.compile("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$");
    private final Pattern domainPattern=Pattern.compile("^[a-zA-Z0-9.\\-]+$");

    //运行指令
    public void run(String command) {
        if (command.startsWith("server ")) {//修改dns服务器指令
            String ip = command.substring(7);
            if (isValidIp(ip)) {
                setDnsServer(ip);
            } else {
                System.out.println("Invalid IP address format.");
            }
        }
        else if(command.startsWith("print ")){//
            String Domain=command.substring(6);
            if (isValidDomain(Domain)){
                MyNsLookUpMain.PacketHandler.runDNSRequest(Domain,true);
            } else {
                System.out.println("Invalid Domain format.");
            }
        } else if (command.equalsIgnoreCase("exit")) {
            MyNsLookUpMain.close();//关闭进程
        } else if (isValidDomain(command)) {//解析指令
            sendDNSRequest(command);
        }  else {
            System.out.println("Invalid command");
        }
    }

    public void PrintInfo(){
        System.out.println();
        System.out.println("DNS Server Address:");
        System.out.println(MyNsLookUpMain.usingDNS.getHostAddress());
        System.out.println();
    }
    public void PrintInput() {
        System.out.print("> ");
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

    private boolean isValidDomain(String domain){
        Matcher matcher=domainPattern.matcher(domain);
        return matcher.matches();
    }
}
