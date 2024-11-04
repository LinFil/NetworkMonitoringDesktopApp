package application;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.concurrent.Task;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.chart.BarChart;
import javafx.scene.chart.CategoryAxis;
import javafx.scene.chart.NumberAxis;
import javafx.scene.chart.PieChart;
import javafx.scene.chart.XYChart;
import javafx.scene.control.Label;
import javafx.scene.control.MenuBar;
import javafx.scene.control.TextArea;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javafx.stage.FileChooser.ExtensionFilter;
import javafx.scene.control.MenuItem;

import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

public class OfflineController implements Initializable {

    @FXML
    private TextArea fileChooserTextArea;
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
    private PieChart applicationChart;
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
    private MenuBar menuBar;
    @FXML
    private Label packetLossLabel;
    
    
    private String fileName;
    private Capture capture;
    Set<String> connections = new HashSet<>();
    int tcpCount = 0;
    int udpCount = 0;
    int httpCount = 0;
    int smtpCount = 0;
    int ftpCount = 0;
    int dnsCount = 0;
    int httpsCount = 0;
    double bandwidth;
    double speed;
    double throughput;
    double jitter;
    double latency;
    
   
    final AtomicInteger byteCount = new AtomicInteger(0);
    @FXML
    private BarChart<String, Number> packetChartBarChart;
    
    @FXML
    private BarChart<String, Integer> topTalkersBarChart;
    @FXML
    private CategoryAxis xAxis;
    @FXML
    private NumberAxis yAxis;
    Map<String, Integer> ipAddressCountMap = new HashMap<>();
    @FXML
    private TextArea packetPayloadtextArea;
   
   
    @FXML
    private Label gatewayLabel;
    
    @FXML
    private Label linkSpeedLabel;
    @FXML
    private Label receivedPacketsLabel;
    @FXML
    private Label sentPacketsLabel;
    private Stage stage;
    private Scene scene;
    private Parent root;
    LoginController loginController = new LoginController();
    String username;
   
   
    
    
    private double linkSpeed;
    @FXML
    private Label packetCountLabel;
    
    

    

   
   
    


    @Override
    public void initialize(URL location, ResourceBundle resources) {
    	 
    	    
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

    @FXML
    public void fileChooser(ActionEvent e) {
        File selectedFile = chooseFile();

        if (selectedFile != null) {
            fileName = selectedFile.getAbsolutePath();
            capture = new Capture(fileName);
            


            Task<Void> task = new Task<Void>() {
                @Override
                protected Void call() throws IOException {
                    processPcapFile();
                    initializeTransportPieChart();
                    initializeApplicationPieChart();
                    initializeTalkersBarChart();
                    initializepacketChartBarChart();
                    
                    return null;
                }
            };

            new Thread(task).start();
        }
    }

    private File chooseFile() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Open Resource File");

        // Set initial directory for file chooser dialog
        File initialDirectory = new File(System.getProperty("user.home"));
        fileChooser.setInitialDirectory(initialDirectory);

        // Add filters for the file chooser dialog
        fileChooser.getExtensionFilters().addAll(new FileChooser.ExtensionFilter("Pcap Files", "*.pcap", "*.cap"));

        // Show file chooser dialog
        return fileChooser.showOpenDialog(null);
    }

    private void processPcapFile() throws IOException {
        capture.startCapture(fileName);
        username = loginController.getUsername();
        new Thread(() -> {
            for (PcapPacket packet : capture.packets) {
                try {
                	processPacket(packet);
                    Platform.runLater(() -> {
                        packetCountLabel.setText(capture.packets.size() + " packets");
                        packetLossLabel.setText(capture.getLostPacketCount() + " packets");
                        receivedPacketsLabel.setText(capture.getReceivedPacketCount() + " packets");
                        sentPacketsLabel.setText(capture.getSentPacketCount() + " packets");
                        usernameLabel.setText(username);
                    });
                    labels();
                    Thread.sleep(200); // Delay between packets
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        }).start();
    }




    private void labels() {
    	
        bandwidth = capture.calculateOfflineBandwidth();
        String formattedBandwidth = String.format("%.2f", bandwidth);
        speed = capture.calculateOfflineSpeed();
        String formattedSpeed = String.format("%.2f", speed);
        throughput = capture.calculateOfflineThroughput();
        String formattedThroughput = String.format("%.2f", throughput);
        jitter = capture.calculateJitter();
        String formattedJitter = String.format("%.2f", jitter);
        latency = capture.calculateLatency();
        String formattedLatency = String.format("%.2f", latency);
        linkSpeed = capture.calculateLinkSpeed();
        String formattedLinkSpeed = String.format("%.2f", linkSpeed);
        
       
     
    Platform.runLater(() -> {
        bandwidthLabel.setText(formattedBandwidth + " Mbps");
        speedLabel.setText(formattedSpeed + " Mbps");
        throughputLabel.setText(formattedThroughput + " Mbps");
        jitterLabel.setText(formattedJitter + " Mbps");
        latencyLabel.setText(formattedLatency + " Mbps");
        linkSpeedLabel.setText(formattedLinkSpeed + " Mbps");
        
        gatewayLabel.setText(capture.getNetworkGateway());
        deviceNameLabel.setText(capture.getDeviceName());
        
        descriptionLabel.setText(capture.getDescription());
        macAddressLabel.setText(capture.getMacAddress());
        ipAddressLabel.setText(capture.getIpAddress());
        maskLabel.setText(capture.getNetworkMask());
    });
}
   
   
   
    private void processPacket(PcapPacket packet) throws InterruptedException {
    	capture.processPacketState(packet);
        Ip4 ip = new Ip4();
        Tcp tcp = new Tcp();
        Udp udp = new Udp();
        

        if (packet.hasHeader(ip)) {
            String ip1 = org.jnetpcap.packet.format.FormatUtils.ip(ip.source());
            String ip2 = org.jnetpcap.packet.format.FormatUtils.ip(ip.destination());

            if (packet.hasHeader(tcp)) {
                tcpCount++;

                if (ip1.compareTo(ip2) < 0) {
                    // ip1 < ip2, so use (ip1, ip2) as the key
                    String connection = String.format("%s -> %s", ip1, ip2);
                    if (!connections.contains(connection)) {
                        connections.add(connection);
                        Platform.runLater(() -> {
                            fileChooserTextArea.appendText(connection + "\n");
                        });
                    }
                } else if (ip1.compareTo(ip2) > 0) {
                    // ip2 < ip1, so use (ip2, ip1) as the key
                    String connection = String.format("%s -> %s", ip2, ip1);
                    if (!connections.contains(connection)) {
                        connections.add(connection);
                        Platform.runLater(() -> {
                            fileChooserTextArea.appendText(connection + "\n");
                        });
                    }
                }
            }

            if (packet.hasHeader(udp)) {
                udpCount++;
            }
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
            } else if (srcPort == 443 || dstPort == 443) {
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

  


    @FXML
    public void initializeTransportPieChart() {
        Thread transportLayerPieChart = new Thread(() -> {
            while (true) {
                Platform.runLater(() -> {
                    transportChart.getData().clear();

                    PieChart.Data tcp = new PieChart.Data("TCP", tcpCount);
                    PieChart.Data udp = new PieChart.Data("UDP", udpCount);

                    // Clear previous data and add new data
                    transportChart.getData().addAll(tcp, udp);
                });

                try {
                    Thread.sleep(5000); // Delay between updates
                } catch (InterruptedException ex) {
                    // Exception handling...
                }
            }
        });

        transportLayerPieChart.setDaemon(true); // Set the thread as a daemon thread
        transportLayerPieChart.start();
    }

    @FXML
    public void initializeApplicationPieChart() {
        Thread applicationLayerPieChart = new Thread(() -> {
            while (true) {
                Platform.runLater(() -> {
                    applicationChart.getData().clear();

                    PieChart.Data http = new PieChart.Data("HTTP", httpCount);
                    PieChart.Data smtp = new PieChart.Data("SMTP", smtpCount);
                    PieChart.Data ftp = new PieChart.Data("FTP", ftpCount);
                    PieChart.Data dns = new PieChart.Data("DNS", dnsCount);
                    PieChart.Data https = new PieChart.Data("HTTPS", httpsCount);

                    // Clear previous data and add new data
                    applicationChart.getData().addAll(http, smtp, ftp, dns,https);
                });

                try {
                    Thread.sleep(5000); // Delay between updates
                } catch (InterruptedException ex) {
                    // Exception handling...
                }
            }
        });

        applicationLayerPieChart.setDaemon(true); // Set the thread as a daemon thread
        applicationLayerPieChart.start();
    }
    @FXML
    public void initializepacketChartBarChart() {
        CategoryAxis xAxis = new CategoryAxis();
        NumberAxis yAxis = new NumberAxis();

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
                	packetChartBarChart.setTitle("Packet Statistics");
                    xAxis.setLabel("Packet Type");
                    yAxis.setLabel("Count");
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


}
