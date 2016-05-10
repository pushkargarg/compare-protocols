README:

External Libraries:
The module has been developed using JAVA language and JnetPcap library. For visualization tool, D3 has been used.

Design:
Pcap packets are captured through Wireshark. Pcap files are given as input to QUICParser and SpdyParser which output the CSV files containing information such as source and destination ip address, port number, sequence and acknowledgement numbers, TLS information(in case of SPDY) and server configurations, client hello and server rejection (in case of QUIC) and performance matrix. The visualization tool uses these csv files as input in order to display data.


Directory Hierarchy:
1) Captures (Directory):
   Contains all the pcap files captured through wireshark for different websites for each of the three protocols.

2) HTTP Csv (Directory):
   Contains the csv files returned by parser for HTTP protocol pcap files.

3) QUIC Csv (Directory):
   Contains the csv files returned by parser for QUIC protocol pcap files.

4) SPDY Csv (Directory):
   Contains the csv files returned by parser for SPDY protocol pcap files.

5) ProjectSource (Directory):
   Cotains the java source code for parsers and helpers. "src" subdirectrory contains all the files.

6) PageLoad.csv :
   File containing page load time values observed for all three protocols across different websites.

7) throughput.csv :
   File containing throughput values observed for all three protocols across different websites.

Source Files Description:

1) QuicParser.java -> Parser for QUIC protocol packets. Takes pcap file name as input argument and gives three CVS files as output. First for handshake connections, second for reconnection flow and last for overall flow information. Also returns page load time and throughput. 

2) SpdyParser.java -> Parser for SPDY and HTTP/1.1 packets. Takes pcap file name as input and returns the csv file containing flow information based on protocol the packet belongs to. Also returns page load time and throughput.

3) ParserHelper.java -> Contains common methods to be used by both the parsers in order to extract bit level information.

4) PacketInfo.java -> Bean class to store all the required fields that are then written to csv file.

5) CreateCSV.java -> Class containing methods to write parsed data to csv file.