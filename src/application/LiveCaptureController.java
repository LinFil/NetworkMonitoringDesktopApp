package application;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.concurrent.Task;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.chart.BarChart;
import javafx.scene.chart.CategoryAxis;
import javafx.scene.chart.NumberAxis;
import javafx.scene.chart.PieChart;
import javafx.scene.chart.XYChart;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.stage.Stage;
import javafx.scene.control.MenuItem;


public class LiveCaptureController {

    @FXML
    private TextArea textArea;
    @FXML
    private TextArea packetPayloadtextArea;
    @FXML
    private Label usernameLabel;
    @FXML
    private PieChart transportChart;
    @FXML
    private Label bandwidthLabel;
    @FXML
    private Label speedLabel;
    @FXML
    private Label throughputLabel;
    @FXML
    private Label jitterLabel;
    @FXML
    private Label latencyLabel;
    @FXML
    private Label packetLossLabel;
    @FXML
    private Label deviceNameLabel;
    @FXML
    private Label descriptionLabel;
    @FXML
    private Label macAddressLabel;
    @FXML
    private Label ipAddressLabel;
    @FXML
    private Label maskLabel;
    @FXML
    private Label gatewayLabel;
    
    @FXML
    private Label linkSpeedLabel;
    @FXML
    private Label receivedPackets;
    @FXML
    private Label packetCountLabel;
    @FXML
    private Label sentPackets;
    double bandwidth;
    double speed;
    double throughput;
    double jitter;
    double latency;
    final AtomicInteger byteCount = new AtomicInteger(0);
    Set<String> connections = new HashSet<>();
    @FXML
    private PieChart applicationChart;
    @FXML
    private BarChart<String, Number> packetChartBarChart;
    @FXML
    private BarChart<String, Integer> topTalkersBarChart;
    @FXML
    private CategoryAxis xAxis;
    @FXML
    private NumberAxis yAxis;
   
   
    
    
    Map<String, Integer> ipAddressCountMap = new HashMap<>();

   

    int tcpCount = 0;
    int udpCount = 0;
    int httpCount = 0;
    int smtpCount = 0;
    int ftpCount = 0;
    int dnsCount = 0;
    int httpsCount = 0;
    
    Capture capture = new Capture();
    int receivedPacketCount;
    long sentPacketCount ;
    long lostPacketCount ;
    private Stage stage;
    private Scene scene;
    private Parent root;
    private String deviceName;
    private String description;
    private String macAddress;
    private String ipAddress;
    private String mask;
    private String gateway;
   
    private double linkSpeed;
    LoginController loginController = new LoginController();
    
   
    
    @FXML
    public void initialize() {
        Task<Void> task = new Task<Void>() {
            @Override
            protected Void call() throws Exception {
                while (true) {
                    try {
                        process();
                        labels();
                    } catch (Exception ex) {
                        ex.printStackTrace();
                        // Exception handling...
                    }
                }
            }
        };
        new Thread(task).start();
        applicationChart();
        transportChart();
        packetChartBarChart();
        initializeTalkersBarChart();
    }
    @FXML
    public void goBack(ActionEvent e) throws IOException {
        Parent root = FXMLLoader.load(getClass().getResource("SecondInterface.fxml"));
        stage = (Stage) ((MenuItem) e.getSource()).getParentPopup().getOwnerWindow();
        scene = new Scene(root);
        stage.setScene(scene);
        stage.show();
    }
    @FXML
    public void close(ActionEvent e) {
    	// Exit the whole application
        System.exit(0);
    }

    public void process() {
        capture.startCapture();
        List<PcapPacket> packets = capture.packets; // Retrieve packets from capture instance
        
       
        if (!packets.isEmpty()) {
            PcapPacket packet = packets.get(packets.size() - 1);
            capture.processPacketState(packet);
            
            Platform.runLater(() -> {
                packetCountLabel.setText(""+capture.packets.size() + " packets");
                
                usernameLabel.setText(loginController.getUsername());
                });

            Ip4 ip = new Ip4();
            Tcp tcp = new Tcp();
            Udp udp = new Udp();
            if (packet.hasHeader(ip) && packet.hasHeader(tcp)) {
                String ip1 = org.jnetpcap.packet.format.FormatUtils.ip(ip.source());
                String ip2 = org.jnetpcap.packet.format.FormatUtils.ip(ip.destination());
                tcpCount++;

                if (ip1.compareTo(ip2) < 0) {
                    String connection = String.format("%s -> %s", ip1, ip2);
                    if (!connections.contains(connection)) {
                        connections.add(connection);
                        Platform.runLater(() -> {
                            textArea.appendText(connection + "\n");
                        });
                    }
                } else if (ip1.compareTo(ip2) > 0) {
                    String connection = String.format("%s -> %s", ip2, ip1);
                    if (!connections.contains(connection)) {
                        connections.add(connection);
                        Platform.runLater(() -> {
                            textArea.appendText(connection + "\n");
                        });
                    }
                }

                
            }
            if (packet.hasHeader(udp)) {
                udpCount++;
            }
            if (packet.hasHeader(tcp)) {
                int srcPort = tcp.source();
                int dstPort = tcp.destination();

                if (srcPort == 80 || dstPort == 80) {
                    httpCount++;
                } else if (srcPort == 25 || dstPort == 25) {
                    smtpCount++;
                } else if (srcPort == 21 || dstPort == 21) {
                    ftpCount++;
                }else if (srcPort == 443 || dstPort == 443) {
                    httpsCount++;
                }
            }
            if (packet.hasHeader(udp)) {
                int srcPort = udp.source();
                int dstPort = udp.destination();

                if (srcPort == 53 || dstPort == 53) {
                    dnsCount++;
                }
            }
            if (packet.hasHeader(ip)) {
                String sourceIpAddress = org.jnetpcap.packet.format.FormatUtils.ip(ip.source());
                String destinationIpAddress = org.jnetpcap.packet.format.FormatUtils.ip(ip.destination());

                // Update the count for source IP address
                ipAddressCountMap.merge(sourceIpAddress, 1, Integer::sum);

                // Update the count for destination IP address
                ipAddressCountMap.merge(destinationIpAddress, 1, Integer::sum);
            }
            byte[] payload = packet.getByteArray(0, packet.size());
            String payloadString = new String(payload, StandardCharsets.UTF_8);
            Platform.runLater(() -> {
            packetPayloadtextArea.appendText("PACKET PAYLOAD:" + "\n");
            packetPayloadtextArea.appendText(payloadString + "\n");
            });
        }
        
    }
    

    

    

    public void transportChart() {
        Thread transportLayerPieChart = new Thread(() -> {
            while (true) {
                Platform.runLater(() -> {
                    PieChart.Data tcp = new PieChart.Data("TCP", tcpCount);
                    PieChart.Data udp = new PieChart.Data("UDP", udpCount);
                    // Clear previous data and add new data
                    transportChart.getData().setAll(tcp, udp);
                });

                try {
                    Thread.sleep(5000); // Delay between updates
                } catch (InterruptedException ex) {
                    ex.printStackTrace();
                    // Exception handling...
                }
            }
        });

        transportLayerPieChart.setDaemon(true); // Set the thread as a daemon thread
        transportLayerPieChart.start();
    }

    private void labels() {
        bandwidth = capture.calculateLiveBandwidth();
        String formattedBandwidth = String.format("%.2f", bandwidth);
        speed = capture.calculateLiveSpeed();
        String formattedSpeed = String.format("%.2f", speed);
        throughput = capture.calculateLiveThroughput();
        String formattedThroughput = String.format("%.2f", throughput);
        jitter = capture.calculateJitter();
        String formattedJitter = String.format("%.2f", jitter);
        latency = capture.calculateLatency();
        String formattedLatency = String.format("%.2f", latency);
        linkSpeed = capture.calculateLinkSpeed();
        String formattedLinkSpeed = String.format("%.2f", linkSpeed);
       
        receivedPacketCount = capture.getReceivedPacketCount();
        sentPacketCount = capture.getSentPacketCount();
        lostPacketCount = capture.getLostPacketCount();
        deviceName = capture.getDeviceName();
        description = capture.getDescription();
        macAddress = capture.getMacAddress();
        ipAddress = capture.getIpAddress();
        mask = capture.getNetworkMask();
        gateway = capture.getNetworkGateway();
       
        
        
        Platform.runLater(() -> {
            bandwidthLabel.setText(formattedBandwidth + " Mbps");
            speedLabel.setText(formattedSpeed + " Mbps");
            throughputLabel.setText(formattedThroughput + " Mbps");
            jitterLabel.setText(formattedJitter + " Mbps");
            latencyLabel.setText(formattedLatency + " Mbps");
            packetLossLabel.setText(lostPacketCount + " packets");
            receivedPackets.setText(receivedPacketCount + " packets");
            sentPackets.setText(sentPacketCount + " packets");

            
            
            
            linkSpeedLabel.setText(formattedLinkSpeed + " Mbps");
            deviceNameLabel.setText(deviceName);
            descriptionLabel.setText(description);
            macAddressLabel.setText(macAddress);
            ipAddressLabel.setText(ipAddress);
            maskLabel.setText(mask);
            gatewayLabel.setText(gateway);
           
        });
    }

   
    
   
    

    public void applicationChart() {
        Thread applicationLayerPieChart = new Thread(() -> {
            while (true) {
                Platform.runLater(() -> {
                    PieChart.Data http = new PieChart.Data("HTTP", httpCount);
                    PieChart.Data smtp = new PieChart.Data("SMTP", smtpCount);
                    PieChart.Data ftp = new PieChart.Data("FTP", ftpCount);
                    PieChart.Data dns = new PieChart.Data("DNS", dnsCount);
                    PieChart.Data https = new PieChart.Data("HTTPS", httpsCount);

                    // Clear previous data and add new data
                    applicationChart.getData().setAll(http, smtp, ftp, dns,https);
                });
                try {
                    Thread.sleep(5000); // Delay between updates
                } catch (InterruptedException ex) {
                    ex.printStackTrace();
                    // Exception handling...
                }
            }
        });
        applicationLayerPieChart.setDaemon(true); // Set the thread as a daemon thread
        applicationLayerPieChart.start();
    }
    public void packetChartBarChart() {
        CategoryAxis xAxis = new CategoryAxis();
        NumberAxis yAxis = new NumberAxis();

        packetChartBarChart.setTitle("Packet Statistics");
        xAxis.setLabel("Packet Type");
        yAxis.setLabel("Count");

        Thread packetChartThread = new Thread(() -> {
            while (true) {
                int received = capture.getReceivedPacketCount();
                int sent = capture.getSentPacketCount();
                int lost = capture.getLostPacketCount();

                XYChart.Series<String, Number> series = new XYChart.Series<>();
                series.getData().add(new XYChart.Data<>("Received", received));
                series.getData().add(new XYChart.Data<>("Sent", sent));
                series.getData().add(new XYChart.Data<>("Lost", lost));

                Platform.runLater(() -> {
                    // Clear existing data
                    packetChartBarChart.getData().clear();

                    // Add new data
                    packetChartBarChart.getData().add(series);
                });

                try {
                    Thread.sleep(5000); // Delay between updates
                } catch (InterruptedException ex) {
                    ex.printStackTrace();
                    // Exception handling...
                }
            }
        });

        packetChartThread.setDaemon(true); // Set the thread as a daemon thread
        packetChartThread.start();
    }
   

    @FXML
    public void initializeTalkersBarChart() {
        Thread talkersBarChartThread = new Thread(() -> {
            while (true) {
                Platform.runLater(() -> {
                    topTalkersBarChart.setAnimated(true); // Disable animation for immediate updates
                    topTalkersBarChart.setTitle("Top Talkers");
                    xAxis.setLabel("IP Address");
                    yAxis.setLabel("Count");

                    // Clear previous data
                    topTalkersBarChart.getData().clear();

                 // Sort the IP addresses by count in descending order
                    List<Map.Entry<String, Integer>> sortedList = new ArrayList<>(ipAddressCountMap.entrySet());
                    sortedList.sort(Map.Entry.comparingByValue(Comparator.reverseOrder()));
                    
                 // Take only the top 5 IP addresses
                    List<Map.Entry<String, Integer>> top3List = sortedList.subList(0, Math.min(3, sortedList.size()));
                 
                 // Create a series for the bar chart
                    XYChart.Series<String, Integer> series = new XYChart.Series<>();
                    for (Map.Entry<String, Integer> entry : top3List) {
                        series.getData().add(new XYChart.Data<>(entry.getKey(), entry.getValue()));
                    }

                    // Add new data to the bar chart
                    topTalkersBarChart.getData().add(series);
                



                   

                    
                });

                try {
                    Thread.sleep(5000); // Delay between updates
                } catch (InterruptedException ex) {
                    // Exception handling...
                }
            }
        });

        talkersBarChartThread.setDaemon(true); // Set the thread as a daemon thread
        talkersBarChartThread.start();
    }

  

   
   

}
