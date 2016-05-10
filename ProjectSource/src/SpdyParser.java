import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import java.util.*;
import org.jnetpcap.util.PcapPacketArrayList;

/*
 * The SPDY/HTTP Parser. Takes pcap file name as input argument and creates csv file containing information such as 
 * source and destination IP addresses, port numbers, sequence number, acknowledgement number, window size. Also identifies if packet is TLS in case of SPDY.
 */
public class SpdyParser implements ParsePacketInfo {
	private static Queue<Long> toDoPackets;
	static String filename = "";
	private static final int seqIndex = 38;
	private static final int ackIndex = 42;
	private static final int windowSizeIndex = 48;
	private static long seqNo = 0;
	public long dstPort, srcPort, packetLength, frameNo, time, seq, ack, windowSize;
	public String srcIP, dstIP;
	public boolean isAck, isSyn, isFin, fromServer, fromClient = true, isTls;
	public static String outFileName = "";
	public static boolean countFlag = false;
	public static boolean winFlag = false;
	public static long ssthresh;
	public static Map<String, Connection> connections = new HashMap<String, Connection>();
	public static List<PacketInfo> packetsInfo = new ArrayList<PacketInfo>();

	public static void main(String args[]) throws Exception {
		toDoPackets = new LinkedList<Long>();
		if (args.length < 1) {
			System.out.println("Pcap File name not specified!!");
			System.exit(0);
		}
		filename = args[0];
		outFileName = filename + ".csv";
		CreateCSV outFile = new CreateCSV(outFileName);

		int counter = 0;
		long timeDiff = 0;
		boolean threshold = false;
		long totalPacketSize = 0;
		long lastObservedTime = 0;
		long endPacketTm = 0;
		double throughput;

		PcapPacketArrayList packets = ParserHelper.readOfflineFiles(filename);
		final Tcp tcp = new Tcp();
		Ip4 ip = new Ip4();
		long offset = 1;
		PcapPacket firstPack = packets.get(0);
		toDoPackets.add(getNumberData(firstPack, seqIndex));
		while (!toDoPackets.isEmpty()) {
			seqNo = toDoPackets.remove();
			offset = 1;
			for (PcapPacket packet : packets) {
				SpdyParser obj = new SpdyParser();
				obj.fromClient = true;
				if (packet.hasHeader(Tcp.ID)) {
					packet.getHeader(tcp);
					obj.dstPort = tcp.destination();
					obj.srcPort = tcp.source();

					if (obj.dstPort == 443 || obj.dstPort == 80 || obj.srcPort == 443 || obj.srcPort == 80) {
						PacketInfo packetInfo = new PacketInfo();
						obj.packetLength = tcp.getLength();
						obj.frameNo = packet.getFrameNumber();

						if (packet.hasHeader(ip)) {
							obj.srcIP = FormatUtils.ip(packet.getHeader(ip).source());
							obj.dstIP = FormatUtils.ip(packet.getHeader(ip).destination());
						}

						obj.time = packet.getCaptureHeader().timestampInMillis();
						if (counter == 0) {
							timeDiff = obj.time;
							obj.time = 0;
							counter++;
						} else {
							obj.time -= timeDiff;
						}

						// set threshold to ignore reconnection packets
						if (obj.time - lastObservedTime > 10000) {
							threshold = true;
						}

						if (!threshold) {
							totalPacketSize += packet.size();
							endPacketTm = obj.time;
						}

						packetInfo.setFrameNo(packet.getFrameNumber());
						packetInfo.setDstPort(obj.dstPort);
						packetInfo.setSrcPort(obj.srcPort);
						packetInfo.setDestinationIP(obj.dstIP);
						packetInfo.setSourceIP(obj.srcIP);
						packetInfo.setTimeStamp(obj.time);
						packetInfo.setAck(obj.isAck);

						Byte publicFlag = packet.getByte(47);
						obj.isAck = ParserHelper.getBit(4, publicFlag) == 1 ? true : false;
						obj.isSyn = ParserHelper.getBit(1, publicFlag) == 1 ? true : false;
						obj.isFin = ParserHelper.getBit(0, publicFlag) == 1 ? true : false;
						obj.ack = getNumberData(packet, ackIndex);
						obj.seq = getNumberData(packet, seqIndex);
						packetInfo.setSeqNo(obj.seq);
						packetInfo.setAckNo(obj.ack);
						obj.windowSize = getNumberData(packet, windowSizeIndex, 2);
						obj.isTls = false;
						if (tcp.getPayloadLength() > 0 && getNumberData(packet, 54, 1) == 22) {
							obj.isTls = true;
						}
						if (seqNo == 0) {
							seqNo = obj.seq;
						}
						// segregate client and server packets
						if (obj.ack == seqNo + offset) {
							obj.fromServer = true;
							obj.fromClient = false;
							Connection conn = connections.get(obj.dstIP + obj.srcIP + obj.dstPort);
							conn.serverToClientPackets.add(packetInfo);
							outFile.writeToFile(obj);
						} else {
							if (obj.seq == seqNo + offset || obj.seq == seqNo) {
								offset += ip.length() - (tcp.getLength() + ip.getLength());
								if (obj.isFin)
									offset++;
								obj.fromClient = true;
								obj.fromServer = false;
								Connection conn = connections.get(obj.srcIP + obj.dstIP + obj.srcPort);
								if (conn == null) {
									conn = new Connection();
									conn.setId(obj.srcIP + obj.dstIP + obj.srcPort);
									connections.put(conn.getId(), conn);
								}
								if (!winFlag) {
									ssthresh = obj.windowSize;
									winFlag = true;
								}
								conn.clientToServerPackets.add(packetInfo);
								outFile.writeToFile(obj);
							} else {
								// condition to identify parallel connections
								if (obj.seq != seqNo && obj.isSyn && !obj.isAck && countFlag == false) {
									toDoPackets.add(obj.seq);
								}
							}
						}
					}
				}
			}
			outFile.insertEmpty();
			countFlag = true;
		}
		throughput = totalPacketSize / endPacketTm;
		System.out.println("Page load time is : " + endPacketTm/1000);
		System.out.println("Throughput is : " + throughput * 1000 + " bytes per sec.");

		// getAvgRtt();
		// getCongestionWindowIncrement();
	}

	/**
	 * method to calculate congestion window size increment with time
	 */
	private static void getCongestionWindowIncrement() {
		List<Long> cwnd = new ArrayList<Long>();
		List<Long> timeCwnd = new ArrayList<Long>();
		cwnd.add((long) 3);
		timeCwnd.add((long) 0);
		long previousValue = 0;
		System.out.println("ssthresh is : " + ssthresh);
		for (Map.Entry<String, Connection> entry : connections.entrySet()) {
			Connection connect = entry.getValue();
			List<PacketInfo> serverPkts = connect.getServerToClientPackets();
			for (int j = 1; j < serverPkts.size(); j++) {
				PacketInfo pkt = serverPkts.get(j);
				if (pkt.getAckNo() != serverPkts.get(j - 1).getAckNo()) {
					previousValue = cwnd.get(cwnd.size() - 1);
					if (previousValue * 2 > ssthresh) {
						cwnd.add(previousValue + 1);
					} else {
						cwnd.add(previousValue * 2);
					}
					timeCwnd.add(pkt.getTimeStamp());
				}
			}
		}
		for (int i = 0; i < cwnd.size(); i++) {
			System.out.println("Time : " + timeCwnd.get(i));
			System.out.println("CWND : " + cwnd.get(i));
		}
	}

	/**
	 * method to calculate average rtt
	 */
	private static void getAvgRtt() {
		double alpha = 0.875;
		double oldRtt = 0;
		double avgRtt = 0;
		double newRtt;
		for (Map.Entry<String, Connection> entry : connections.entrySet()) {
			Connection connect = entry.getValue();
			List<PacketInfo> clientPkts = connect.getClientToServerPackets();
			List<PacketInfo> serverPkts = connect.getServerToClientPackets();
			for (int i = 0; i < clientPkts.size(); i++) {
				PacketInfo pkt = clientPkts.get(i);
				for (int j = 0; j < serverPkts.size(); j++) {
					if (serverPkts.get(j).getAckNo() == pkt.getSeqNo() + 1) {
						if (i == 0) {
							newRtt = serverPkts.get(j).getTimeStamp() - pkt.getTimeStamp();
							if (newRtt < 5000) {
								avgRtt = (alpha * oldRtt) + (1 - alpha) * newRtt;
								oldRtt = avgRtt;
							}
							break;
						} else {
							if (pkt.getSeqNo() != clientPkts.get(i - 1).getSeqNo()) {
								newRtt = serverPkts.get(j).getTimeStamp() - pkt.getTimeStamp();
								if (newRtt < 5000) {
									avgRtt = (alpha * oldRtt) + (1 - alpha) * newRtt;
									oldRtt = avgRtt;
								}
								break;
							}
						}
					}
				}
			}
		}

		System.out.println("Avg RTT is : " + avgRtt);
	}

	public static long getNumberData(PcapPacket packet, int start) {
		return getNumberData(packet, start, 4);
	}

	public static long getNumberData(PcapPacket packet, int start, int size) {
		long seq = 0;
		for (int i = 0; i < size; i++) {
			seq = seq << 8;
			seq += packet.getByte(start + i) & 0xFF;
		}
		return seq;
	}

	@Override
	public String getHeaderString() {
		return "frame,dstport,srcport,destIP,srcIP,timestamp,seqNo"
				+ ",ackNo,isSyn,isAck,isFin,isTLS,length,fromClient,fromServer,windowSize";
	}

	@Override
	public String getAllString() {
		return String.format("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s", this.frameNo, this.dstPort,
				this.srcPort, this.dstIP, this.srcIP, this.time, this.seq, this.ack, this.isSyn, this.isAck, this.isFin,
				this.isTls, this.packetLength, this.fromClient, this.fromServer, this.windowSize);
	}
}
