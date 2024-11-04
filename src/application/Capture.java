 /*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/javafx/FXMLController.java to edit this template
 */
package application;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapAddr;
import org.jnetpcap.PcapIf;
import org.jnetpcap.PcapSockAddr;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

/**
 *
 * @author 
 */
public class Capture {
    String FILENAME ; 
    ArrayList<PcapIf> alldevs  = new ArrayList<>();; 
    Pcap pcap;
    List<PcapPacket> packets = new ArrayList<>();
    int snaplen = 128 * 1024;           
    private int receivedPacketCount = 0;
    private int sentPacketCount = 0;
    private int lostPacketCount =0;
    PcapIf device;
    StringBuilder errbuf = new StringBuilder(); 
    int r = Pcap.findAllDevs(alldevs, errbuf);
    
   
    PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {
        @Override
       public void nextPacket(PcapPacket packet, String user) {
        	packets.add(packet);
        	}
        };
    
        //Offline Constructor
        public Capture(String FILENAME) {
            this.FILENAME = FILENAME;
            //this.alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs
           
            if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
                System.err.printf("Can't read list of devices, error is %s", errbuf.toString());
                return;
            }

           
            PcapIf device  = alldevs.get(0);
                        
            this.pcap = Pcap.openOffline(FILENAME, errbuf);

            if (pcap == null) {
                System.err.printf("Error while opening device for capture: " + errbuf.toString());
                
            }
        }
      //Online Constructor
        public Capture() {
        //this.alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs
        //StringBuilder errbuf = new StringBuilder(); // For any error msgs

        //int r = Pcap.findAllDevs(alldevs, errbuf);
        if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
            System.err.printf("Can't read list of devices, error is %s", errbuf.toString());
            return;
        }
        PcapIf device  = alldevs.get(0);
        
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
        int timeout = 10 * 1000;           // 10 seconds in millis
        this.pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

        if (pcap == null) {
            System.err.printf("Error while opening device for capture: " + errbuf.toString());
        }
    }
     
      public String getFileName() {
        return FILENAME;
    }
      //Calculate bandwidth for offline capture
      public double calculateOfflineBandwidth() {
         // Calculate the total size of captured packets
         long totalSize = 0;
         long startTime = Long.MAX_VALUE;
         long endTime = Long.MIN_VALUE;
         
         for (PcapPacket packet : packets) {
             totalSize += packet.getTotalSize();
             long packetTimestamp = packet.getCaptureHeader().timestampInMillis();
             startTime = Math.min(startTime, packetTimestamp);
             endTime = Math.max(endTime, packetTimestamp);
         }
      // Calculate the capture duration in seconds
         double captureDuration = (endTime - startTime) / 1000.0; // Convert to seconds
         
         // Calculate and return the bandwidth in bytes per second
         return totalSize / captureDuration;
      }

      public double calculateOfflineSpeed() {
    	    if (packets.isEmpty()) {
    	        return 0; // Handle the case when no packets are available
    	    }

    	    long startTime = Long.MAX_VALUE;
    	    long endTime = Long.MIN_VALUE;

    	    for (PcapPacket packet : packets) {
    	        long packetTimestamp = packet.getCaptureHeader().timestampInMillis();
    	        startTime = Math.min(startTime, packetTimestamp);
    	        endTime = Math.max(endTime, packetTimestamp);
    	    }

    	    // Calculate the capture duration in milliseconds
    	    long captureDuration = endTime - startTime;

    	    // Calculate and return the speed in packets per second
    	    return packets.size() / (captureDuration / 1000.0);
    	}

            

      public double calculateLiveSpeed() {
    	    if (packets.isEmpty()) {
    	        return 0; // Handle the case when no packets are available
    	    }

    	    long startTime = System.currentTimeMillis();
    	    long endTime = startTime + 5000; // Capture packets for 5 seconds
    	    int packetCount = 0;

    	    for (PcapPacket packet : packets) {
    	        long packetTimestamp = packet.getCaptureHeader().timestampInMillis();
    	        if (packetTimestamp >= startTime && packetTimestamp <= endTime) {
    	            packetCount++;
    	        }
    	    }

    	    double captureDuration = (endTime - startTime) / 1000.0; // Capture duration in seconds

    	    // Calculate and return the speed in packets per second
    	    return packetCount / captureDuration;
    	}

    	   
      
      public double calculateOfflineThroughput() {
    	    if (packets.isEmpty()) {
    	        return 0; // Handle the case when no packets are available
    	    }

    	    long totalSize = 0;
    	    long startTime = Long.MAX_VALUE;
    	    long endTime = Long.MIN_VALUE;

    	    for (PcapPacket packet : packets) {
    	        totalSize += packet.getTotalSize();
    	        long packetTimestamp = packet.getCaptureHeader().timestampInMillis();
    	        startTime = Math.min(startTime, packetTimestamp);
    	        endTime = Math.max(endTime, packetTimestamp);
    	    }

    	    // Calculate the capture duration in seconds
    	    double captureDuration = (endTime - startTime) / 1000.0; // Convert to seconds

    	    // Calculate and return the throughput in bytes per second
    	    return totalSize / captureDuration;
    	}

      public double calculateLiveThroughput() {
    	    if (packets.isEmpty()) {
    	        return 0; // Handle the case when no packets are available
    	    }

    	    long startTime = System.currentTimeMillis();
    	    long totalBytes = 0;

    	    while (System.currentTimeMillis() - startTime < 5000) { // Capture packets for 5 seconds
    	        long currentBytes = 0;

    	        for (PcapPacket packet : packets) {
    	            int packetLength = packet.getTotalSize(); // Size of the captured packet in bytes
    	            currentBytes += packetLength;
    	        }

    	        totalBytes += currentBytes;

    	        try {
    	            Thread.sleep(1000); // Sleep for 1 second before capturing more packets
    	        } catch (InterruptedException e) {
    	            e.printStackTrace();
    	        }
    	    }

    	    long endTime = System.currentTimeMillis();
    	    long duration = endTime - startTime; // Duration of packet capture in milliseconds
    	    double throughputBps = (totalBytes * 8) / (duration / 1000.0); // Network throughput in bits per second

    	    return throughputBps;
    	}
      public synchronized double calculateLiveBandwidth() {
    	    if (packets.isEmpty()) {
    	        return 0; // Handle the case when no packets are available
    	    }

    	    // Calculate the total size of captured packets
    	    long totalSize = 0;
    	    long startTime = Long.MAX_VALUE;
    	    long endTime = Long.MIN_VALUE;

    	    for (PcapPacket packet : packets) {
    	        int packetSize = Math.min(packet.getTotalSize(), snaplen);
    	        totalSize += packetSize;
    	        long packetTimestamp = packet.getCaptureHeader().timestampInMillis();
    	        startTime = Math.min(startTime, packetTimestamp);
    	        endTime = Math.max(endTime, packetTimestamp);
    	    }

    	    // Calculate the capture duration in seconds
    	    double captureDuration = (endTime - startTime) / 1000.0; // Convert to seconds

    	    // Check for non-zero duration
    	    if (captureDuration == 0) {
    	        return 0; // or handle the division by zero error appropriately
    	    }

    	    // Calculate and return the bandwidth in bytes per second
    	    double bandwidth = (double) totalSize / captureDuration;
    	    return bandwidth;
    	}



        
        
  //Calculate bandwidth for live capture
 
	  
  public void startCapture(String FILENAME){
	     this.pcap.loop(-1, jpacketHandler, "capture");
	    }



		public void startCapture() {
			this.pcap.loop(1, jpacketHandler, "capture");
		}
		
		
		
		
		
		public double calculateJitter() {
		    long previousTimestamp = 0;
		    double sumOfDifferences = 0;
		    int packetCount = 0;

		    for (PcapPacket packet : packets) {
		        long currentTimestamp = packet.getCaptureHeader().timestampInMillis();
		        if (previousTimestamp != 0) {
		            double difference = (currentTimestamp - previousTimestamp) / 1000.0; // Convert to seconds
		            sumOfDifferences += difference;
		            packetCount++;
		        }
		        previousTimestamp = currentTimestamp;
		    }

		    if (packetCount > 1) {
		        double averageDifference = sumOfDifferences / (packetCount - 1);
		        return averageDifference;
		    } else {
		        return 0; // No packets or only one packet, so jitter is zero
		    }
		}

		
		public double calculateLatency() {
		    long minTimestamp = Long.MAX_VALUE;
		    long maxTimestamp = Long.MIN_VALUE;

		    for (PcapPacket packet : packets) {
		        long packetTimestamp = packet.getCaptureHeader().timestampInMillis();
		        minTimestamp = Math.min(minTimestamp, packetTimestamp);
		        maxTimestamp = Math.max(maxTimestamp, packetTimestamp);
		    }

		    if (minTimestamp != Long.MAX_VALUE && maxTimestamp != Long.MIN_VALUE) {
		        return (maxTimestamp - minTimestamp) / 1000.0; // Convert to seconds
		    } else {
		        return 0; // No packets, so latency is zero
		    }
		}
		private boolean isReceivedPacket(PcapPacket packet) {
		    Ip4 ip = new Ip4();
		    Tcp tcp = new Tcp();
		    Udp udp = new Udp();
		    
		    if (packet.hasHeader(ip) && (packet.hasHeader(tcp) || packet.hasHeader(udp))) {
		        String ipdst = org.jnetpcap.packet.format.FormatUtils.ip(ip.destination());
		        
		        if (ipdst.equals("192.168.1.107")) {
		            return true;
		        }
		    }
		    
		    return false;
		}

		private boolean isSentPacket(PcapPacket packet) {
		    Ip4 ip = new Ip4();
		    Tcp tcp = new Tcp();
		    Udp udp = new Udp();
		    
		    if (packet.hasHeader(ip) && (packet.hasHeader(tcp) || packet.hasHeader(udp))) {
		        String ipsrc = org.jnetpcap.packet.format.FormatUtils.ip(ip.source());
		        
		        if (ipsrc.equals("192.168.1.107")) {
		            return true;
		        }
		    }
		    
		    return false;
		}

		


		 public void processPacketState(PcapPacket packet) {
		        if (isReceivedPacket(packet)) {
		            receivedPacketCount++;
		        } else if (isSentPacket(packet)) {
		            sentPacketCount++;
		        } else {
		            lostPacketCount++;
		        }
		    }
	    public int getReceivedPacketCount() {
	        return receivedPacketCount;
	    }

	    public int getSentPacketCount() {
	        return sentPacketCount;
	    }
	    public int getLostPacketCount() {
	        return lostPacketCount;
	    }
	    public String getDeviceName() {
	        if (pcap != null) {
	            for (PcapIf device : alldevs) {
	                return device.getName();
	            }
	        }
	        return null;
	    }

	    public String getDescription() {
	    	 if (pcap != null) {
		            for (PcapIf device : alldevs) {
		                return device.getDescription();
		            }
		        }
		        return null;
	    }
	    public String getMacAddress() {
	    	if (pcap != null && !alldevs.isEmpty()) {
	            PcapIf device = alldevs.get(0);
	            StringBuilder macAddress = new StringBuilder();

	            for (PcapAddr addr : device.getAddresses()) {
	                byte[] mac = addr.getAddr().getData();

	                if (mac != null) {
	                    // Convert MAC address bytes to a readable format
	                    for (int i = 0; i < mac.length; i++) {
	                        macAddress.append(String.format("%02X%s", mac[i], (i < mac.length - 1) ? ":" : ""));
	                    }
	                    break; // Only consider the first MAC address
	                }
	            }

	            return macAddress.toString();
	        }

	        return null;
	    }
	    public String getIpAddress() {
	        if (pcap != null && !alldevs.isEmpty()) {
	            PcapIf device = alldevs.get(0);
	            for (PcapAddr addr : device.getAddresses()) {
	                byte[] ip = addr.getAddr().getData();

	                if (ip != null) {
	                    try {
	                        // Convert IP address bytes to a readable format
	                        InetAddress inetAddress = InetAddress.getByAddress(ip);
	                        return inetAddress.getHostAddress();
	                    } catch (UnknownHostException e) {
	                        e.printStackTrace();
	                    }
	                }
	            }
	        }

	        return null;
	    }
	    
	    
	    public String getNetworkMask() {
	    	 if (pcap != null) {
		            for (PcapIf device : alldevs) {
	        for (PcapAddr addr : device.getAddresses()) {
	            byte[] netmask = addr.getNetmask().getData();

	            if (netmask != null) {
	                // Convert network mask bytes to a readable format
	                return FormatUtils.ip(netmask);
	            }
	        }
		            }}
	        return null;
	    }
	    
	    public String getNetworkGateway() {
	        try {
	            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
	            while (interfaces.hasMoreElements()) {
	                NetworkInterface networkInterface = interfaces.nextElement();
	                for (InterfaceAddress address : networkInterface.getInterfaceAddresses()) {
	                    InetAddress inetAddress = address.getAddress();
	                    if (!inetAddress.isLoopbackAddress() && inetAddress instanceof Inet4Address) {
	                        InetAddress gateway = address.getBroadcast();
	                        if (gateway != null) {
	                            return gateway.getHostAddress();
	                        }
	                    }
	                }
	            }
	        } catch (SocketException e) {
	            e.printStackTrace();
	        }

	        return null;
	    }


	  
       
	    public double calculateLinkSpeed() {
	        long startTime = System.currentTimeMillis();
	        long totalBytes = 0;

	        while (System.currentTimeMillis() - startTime < 5000) { 
	            long currentBytes = 0;

	            for (PcapPacket packet : packets) {
	                int packetLength = packet.getTotalSize(); 
	                currentBytes += packetLength;
	            }

	            totalBytes += currentBytes;

	            try {
	                Thread.sleep(1000); 
	            } catch (InterruptedException e) {
	                e.printStackTrace();
	            }
	        }

	        long endTime = System.currentTimeMillis();
	        long duration = endTime - startTime; 
	        double speedBps = (totalBytes * 8) / (duration / 1000.0); // Network speed in bits per second

	        return speedBps;
	    }
	
	    }
