import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

import java.util.*;

import org.jnetpcap.util.PcapPacketArrayList;

public class SpdyParser implements ParsePacketInfo {
	private static Queue<Long> toDoPackets;
	static String filename = "";
	private static final int seqIndex = 38;
	private static final int ackIndex = 42;
	private static final int windowSizeIndex = 48;
	private static long seqNo = 0;
	public long dstPort, srcPort, packetLength, frameNo, time, seq, ack,windowSize;
	public String srcIP, dstIP;
	public boolean isAck, isSyn, isFin, fromServer, fromClient = true, isTls;
	static String outFileName = "SPDY.csv";
	public static boolean countFlag = false;
	public static void main(String args[]) throws Exception {
		toDoPackets = new LinkedList<Long>();
		final StringBuilder errbuf = new StringBuilder(); // For any error msgs
		if (args.length < 1) {
			filename = "C:\\Users\\shweta\\Documents\\Study Material\\Networks\\Project\\captures\\FinalCaptures\\imageSearchSPDY.pcap";
		} else
			filename = args[0];
		CreateCSV outFile = new CreateCSV(outFileName);
		
		int counter = 0;
		long timeDiff = 0;
		
		PcapPacketArrayList packets = readOfflineFiles(filename);
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
						obj.packetLength = tcp.getLength();
						obj.frameNo = packet.getFrameNumber();
						System.out.println("SPDY Packet Found!!" + obj.packetLength);
						System.out.println("Frame number is : " + obj.frameNo);
						System.out.println("Source port is : " + obj.srcPort);
						System.out.println("Destination port is : " + obj.dstPort);

						if (packet.hasHeader(ip)) {
							obj.srcIP = FormatUtils.ip(packet.getHeader(ip).source());
							obj.dstIP = FormatUtils.ip(packet.getHeader(ip).destination());

							System.out.println("Source IP is: " + obj.srcIP);
							System.out.println("Destination IP is: " + obj.dstIP);
						}

						obj.time = packet.getCaptureHeader().timestampInMillis();
						System.out.println("Timestamp is : " + obj.time);
						
						if(counter == 0){
							timeDiff = obj.time;
							obj.time = 0;
							counter++;
						}
						else{
							obj.time -= timeDiff;
						}

						Byte publicFlag = packet.getByte(47);

						String publicFlags = Integer.toBinaryString(publicFlag);
						System.out.println("Public flags are: " + publicFlags);

						obj.isAck = getBit(4, publicFlag) == 1 ? true : false;
						System.out.println("Ack bit is : " + obj.isAck);

						obj.isSyn = getBit(1, publicFlag) == 1 ? true : false;
						System.out.println("Syn bit is : " + obj.isSyn);

						obj.isFin = getBit(0, publicFlag) == 1 ? true : false;
						System.out.println("Fin bit is : " + obj.isFin);
						obj.ack = getNumberData(packet, ackIndex);
						obj.seq = getNumberData(packet, seqIndex);
						obj.windowSize = getNumberData(packet, windowSizeIndex, 2);
						System.out.println("Sequence Number is: " + obj.seq);
						System.out.println("Acknowledgment Number is: " + obj.ack);
						System.out.println("Window Size is: " + obj.windowSize);
						obj.isTls = false;
						if(tcp.getPayloadLength() > 0 && getNumberData(packet, 54,1) == 22)
						{
							obj.isTls = true;
						}
						if (seqNo == 0) {
							seqNo = obj.seq;
						}
						if (obj.ack == seqNo + offset) {
							System.out.println("From Server");
							obj.fromServer = true;
							obj.fromClient = false;
							outFile.writeToFile(obj);
						} else {
							if (obj.seq == seqNo + offset || obj.seq == seqNo) {
								offset += ip.length() - (tcp.getLength() + ip.getLength());
								if(obj.isFin)
									offset++;
								System.out.println("From Client");
								obj.fromClient = true;
								obj.fromServer = false;
								outFile.writeToFile(obj);
							}
							else
							{
								
								if(obj.seq != seqNo && obj.isSyn && !obj.isAck && countFlag == false)
								{
									toDoPackets.add(obj.seq);
								}
							}
						}
						System.out.println("########################### " + offset + " " + seqNo);
					}
				}
			}
			outFile.insertEmpty();
			countFlag = true;
		}
	}

	public static int getBit(int position, byte ID) {
		return (ID >> position) & 1;
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

	public static PcapPacketArrayList readOfflineFiles(String fileName) {
		final StringBuilder errbuf = new StringBuilder(); // For any error msgs

		// open the selected file
		Pcap pcap = Pcap.openOffline(fileName, errbuf);

		if (pcap == null) {
			System.out.println(errbuf.toString());
		}

		// packet handler to receive packets from the libpcap loop.
		PcapPacketHandler<PcapPacketArrayList> jpacketHandler = new PcapPacketHandler<PcapPacketArrayList>() {

			public void nextPacket(PcapPacket packet, PcapPacketArrayList PaketsList) {

				PaketsList.add(packet);
			}
		};

		try {
			PcapPacketArrayList packets = new PcapPacketArrayList();
			pcap.loop(-1, jpacketHandler, packets);

			return packets;
		} finally {
			// close the pcap handle
			pcap.close();
		}

	}

	@Override
	public String getHeaderString() {
		return "frame,dstport,srcport,destIP,srcIP,timestamp,seqNo"
				+ ",ackNo,isSyn,isAck,isFin,isTLS,length,fromClient,fromServer,windowSize";
	}

	@Override
	public String getAllString() {
		return String.format("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s", this.frameNo, this.dstPort, this.srcPort,
				this.dstIP, this.srcIP, this.time, this.seq, this.ack, this.isSyn, this.isAck, this.isFin,this.isTls,
				this.packetLength, this.fromClient, this.fromServer,this.windowSize);
	}
}
