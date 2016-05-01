import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.packet.structure.JField;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.util.PcapPacketArrayList;

public class QuicParser {

	public static String outFileName_handshake = "googleQUIC_handshake.csv";
	public static String outFileName_reconnection = "googleQUIC_reconnection.csv";
	public static String outFileName = "googleQUIC.csv";
	public static void main(String args[]) throws UnsupportedEncodingException {
		
		if (args.length < 0) {
			System.out.println("Pcap File name not specified!!");
			System.exit(0);
		}
		
		CreateCSV outFile = new CreateCSV(outFileName);
		CreateCSV outFile_handshake = new CreateCSV(outFileName_handshake);
		CreateCSV outFile_reconnection = new CreateCSV(outFileName_reconnection);
		
		Set<String> clients = new HashSet<String>();
		Set<String> servers = new HashSet<String>();
		Map<String, Connection> connections = new HashMap<String, Connection>();
		List<PacketInfo> packetsInfo = new ArrayList<PacketInfo>();
		PcapPacketArrayList packets = readOfflineFiles(
				"C:\\Users\\shweta\\Documents\\Study Material\\Networks\\Project\\captures\\FinalCaptures\\googleQUIC.pcap");
		final Udp udp = new Udp();
		Ip4 ip = new Ip4();
		Payload pl = new Payload();
		for (PcapPacket packet : packets) {
			if (packet.hasHeader(Udp.ID)) {
				packet.getHeader(udp);
				long dstPort = udp.destination();
				long srcPort = udp.source();
				String sourceIP = null;
				String destinationIP = null;

				if (dstPort == 443 || dstPort == 80 || srcPort == 443 || srcPort == 80) {
					System.out.println("Quic Packet Found!!");
					PacketInfo packetInfo = new PacketInfo();
					System.out.println("Frame number is : " + packet.getFrameNumber());
					System.out.println("Dst port is : " + dstPort);
		
					///////////////////////////////////

					packet.getHeader(pl);

					System.out.printf("payload length=%d\n", pl.getLength());
					byte[] payloadContent = pl.getByteArray(0, pl.size());
					String strPayloadContent = new String(payloadContent);
					//System.out.println("payload content = [" + strPayloadContent + "]");

					//////////////////////////////////////////
					if (packet.hasHeader(ip)) {
						sourceIP = FormatUtils.ip(packet.getHeader(ip).source());
						destinationIP = FormatUtils.ip(packet.getHeader(ip).destination());

						System.out.println("Source IP is: " + sourceIP);
						System.out.println("Destination IP is: " + destinationIP);
					}

					long timeStamp = packet.getCaptureHeader().timestampInMillis();
					System.out.println("Timestamp is : " + timeStamp);

					Byte publicFlag = packet.getByte(42);
					String publicFlags = Integer.toBinaryString(publicFlag);
					System.out.println("Public flags are: " + publicFlags);

					int versionBit = getBit(0, publicFlag);
					System.out.println("Version bit is : " + versionBit);

					int resetBit = getBit(1, publicFlag);
					System.out.println("ResetBit is : " + resetBit);

					String cidBitStr = "";
					for (int i = 2; i < 4; i++) {
						int cidBit = getBit(i, publicFlag);
						cidBitStr = cidBitStr + Integer.toString(cidBit);
					}
					System.out.println("CID bits are: " + cidBitStr);
					int cidLength = 0;
					if (cidBitStr.equals("11")) {
						cidLength = 8;
					} else if (cidBitStr.equals("10")) {
						cidLength = 4;
					} else if (cidBitStr.equals("01")) {
						cidLength = 1;
					} else {
						cidLength = 0;
					}
					String cid = null;
					if (cidLength != 0) {
						cid = getBytesToHexString(packet, 43, 43 + cidLength - 1);
						System.out.println("CID is : " + cid);
					}
					String seqBitStr = "";
					for (int i = 4; i < 6; i++) {
						int seqBit = getBit(i, publicFlag);
						seqBitStr = seqBitStr + Integer.toString(seqBit);
					}
					System.out.println("SEQ bits are: " + seqBitStr);

					int seqLength = 0;
					if (seqBitStr.equals("00")) {
						seqLength = 1;
					} else if (seqBitStr.equals("01")) {
						seqLength = 2;
					} else if (seqBitStr.equals("11")) {
						seqLength = 6;
					} else if (seqBitStr.equals("10")) {
						seqLength = 4;
					}

					int seqStart = 0;
					if (versionBit == 1) {
						seqStart = 43 + cidLength + 4;
					} else {
						seqStart = 43 + cidLength;
					}

					long seqNo = getDetails(packet, seqStart, seqStart + seqLength - 1);
					System.out.println("SEQ is : " + seqNo);
					packetInfo.setFrameNo(packet.getFrameNumber());
					packetInfo.setDstPort(dstPort);
					packetInfo.setSrcPort(srcPort);
					packetInfo.setDestinationIP(destinationIP);
					packetInfo.setTimeStamp(timeStamp);
					packetInfo.setCid(cid);
					packetInfo.setSeqNo(seqNo);

					//////////////////////////////

					// JHeader header = new Ip4();

					/*
					 * for (JField field: pl.getFields()) {
					 * System.out.printf("field=%s\n", field.getName()); }
					 * System.out.println("Payload size is : " + pl.size());
					 */

					//////////////////////////////////////

					int messageAuthenticationPosition = seqStart + seqLength + 1;
					int messageAuthLength = 12;
					int frameStart = messageAuthenticationPosition + messageAuthLength;
					System.out.println("First frame start = " + frameStart);
					// System.out.println("Length is : "+
					// packet.getCaptureHeader().hdr_len());

					Byte frameFlag = packet.getByte(frameStart);
					System.out.println("First Frame byte is : " + frameFlag);

					String frameFlags = Integer.toBinaryString(frameFlag);
					System.out.println("First frame flags are: " + frameFlags);

					// int streamFrameStart = getStreamFrameStart(frameStart,
					// frameFlag, frameFlags, seqLength);

					String frameType = "none";
					int streamFrameStart = 0;
					if (strPayloadContent.contains("CHLO") || strPayloadContent.contains("REJ")) {
						while (!frameType.equals("Stream")) {
							System.out.println("Inside while..!!");
							int frameTypeBit1 = getBit(7, frameFlag);
							int frameTypeBit2 = getBit(6, frameFlag);
							if (frameTypeBit1 == 1) {
								frameType = "Stream";
								System.out.println("StreamType Found");
								streamFrameStart = frameStart;
								continue;
							} else if (frameTypeBit1 == 0 && frameTypeBit2 == 1) {
								frameType = "Ack";
								int frameSize = 10;
								System.out.println("StreamType is : " + frameType);
								int largestObsBit1 = getBit(3, frameFlag);
								int largestObsBit2 = getBit(2, frameFlag);
								int largestObsSize = 0;
								if (largestObsBit1 == 0 && largestObsBit2 == 0) {
									largestObsSize = 1;
								} else if (largestObsBit1 == 0 && largestObsBit2 == 1) {
									largestObsSize = 2;
								} else if (largestObsBit1 == 1 && largestObsBit2 == 0) {
									largestObsSize = 4;
								} else if (largestObsBit1 == 1 && largestObsBit2 == 1) {
									largestObsSize = 6;
								}
								System.out.println("Largest Observed size = " + largestObsSize);
								frameSize += largestObsSize;
								int nackBit = getBit(5, frameFlag);
								System.out.println("NACK Bit is : " + nackBit);
								if (nackBit == 1) {
									frameSize += 2;

									/*
									 * int missingPktsBit1 =
									 * getBit(1,frameFlag); int missingPktsBit2
									 * = getBit(0,frameFlag); int
									 * missingPktsSize = 0; if(missingPktsBit1
									 * == 0 && missingPktsBit2 == 0){
									 * missingPktsSize = 1; } else
									 * if(missingPktsBit1 == 0 &&
									 * missingPktsBit2 == 1){ missingPktsSize =
									 * 2; } else if(missingPktsBit1 == 1 &&
									 * missingPktsBit2 == 0){ missingPktsSize =
									 * 4; } else if(missingPktsBit1 == 1 &&
									 * missingPktsBit2 == 1){ missingPktsSize =
									 * 6; }
									 */
								}
								System.out.println("Nack bit is = " + nackBit);
								frameStart += frameSize;
								System.out.println("Frame start = " + frameStart);
								frameFlag = packet.getByte(frameStart);
								System.out.println("Frame byte is : " + frameFlag);
								frameFlags = Integer.toBinaryString(frameFlag);
								System.out.println("Frame flags are: " + frameFlags);
								System.out.println("Frame type is : " + frameType);
								continue;
							} else if (frameFlags.equals("110")) {
								frameType = "Stop_Waiting";
								frameStart = frameStart + 2 + seqLength;
								System.out.println("Frame start = " + frameStart);
								frameFlag = packet.getByte(frameStart);
								System.out.println("Frame byte is : " + frameFlag);
								frameFlags = Integer.toBinaryString(frameFlag);
								System.out.println("Frame flags are: " + frameFlags);
								System.out.println("StreamType is : " + frameType);
								continue;
							}
						}
					}
					////////////////////// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
					int chloTagStart = streamFrameStart;
					int offsetBit1 = getBit(4, frameFlag);
					int offsetBit2 = getBit(3, frameFlag);
					int offsetBit3 = getBit(2, frameFlag);
					int dataLengthBit = getBit(5, frameFlag);
					if (dataLengthBit == 1) {
						chloTagStart += 2;
					}
					System.out.println("Offset bit are : " + offsetBit1 + offsetBit2 + offsetBit3);
					String offsetBits = Integer.toString(offsetBit1) + Integer.toString(offsetBit2) + Integer.toString(offsetBit3);
					if (offsetBits.equals("000")){
						chloTagStart += 0;
					}
					else if(offsetBits.equals("001")){
						chloTagStart += 2;
					}
					else if(offsetBits.equals("010")){
						chloTagStart += 3;
					}
					else if(offsetBits.equals("100")){
						chloTagStart += 4;
					}
					else if(offsetBits.equals("110")){
						chloTagStart += 5;
					}
					else if(offsetBits.equals("101")){
						chloTagStart += 6;
					}
					else if(offsetBits.equals("011")){
						chloTagStart += 7;
					}
					else if(offsetBits.equals("111")){
						chloTagStart += 8;
					}
					if (offsetBit1 == 0) {
						chloTagStart += 1;
					}
					int streamIDBit1 = getBit(1, frameFlag);
					int streamIDBit2 = getBit(0, frameFlag);
					int streamIDSize = 0;
					if (streamIDBit1 == 0 && streamIDBit2 == 0) {
						streamIDSize = 1;
					} else if (streamIDBit1 == 0 && streamIDBit2 == 1) {
						streamIDSize = 2;
					} else if (streamIDBit1 == 1 && streamIDBit2 == 0) {
						streamIDSize = 3;
					} else if (streamIDBit1 == 1 && streamIDBit2 == 1) {
						streamIDSize = 4;
					}

					chloTagStart += streamIDSize;
					System.out.println("CHLO tag start = : " + chloTagStart);
					if (packet.getCaptureHeader().hdr_len() > (chloTagStart + 4)) {
						String chloTag = getTags(packet, chloTagStart, chloTagStart + 3);
						if (chloTag.equals("43484C4F")) {
							System.out.println("Its Client Hello!!");
							clients.add(sourceIP);
							servers.add(destinationIP);
							packetInfo.setChlo(true);
							Connection conn = connections.get(sourceIP + destinationIP);
							if (conn == null) {
								conn = new Connection();
								conn.setId(sourceIP + destinationIP);
								conn.setClientIP(sourceIP);
								conn.setServerIP(destinationIP);
								System.out.println("Client is : " + conn.getClientIP());
								System.out.println("Server is : " + conn.getServerIP());
								connections.put(conn.getId(), conn);
							}
							long tagNo = getDetails(packet, chloTagStart + 4, chloTagStart + 4);
							System.out.println("++++++++++++++++++++++++++++++++" + tagNo);
							int tagsStart = chloTagStart + 8;
							int SCIDoffSet = 0;
							for (int ti = 0; ti < tagNo; ti++) {
								String type = getTags(packet, tagsStart, tagsStart + 3);
								if (type.equals("53434944")) {
									System.out.println("Getting something");
									SCIDoffSet = (int) getDetails(packet, tagsStart + 5, tagsStart + 5);
									SCIDoffSet = SCIDoffSet << 8;
									SCIDoffSet += (int) getDetails(packet, tagsStart + 4, tagsStart + 4);

									System.out.println("---Offset length is : " + SCIDoffSet);

								}
								tagsStart += 8;
							}
							if (SCIDoffSet != 0) {
								int SCIDvalue = tagsStart + SCIDoffSet - 16;
								String scidValue = getTags(packet, SCIDvalue, SCIDvalue + 15);
								System.out.println("SCID value is : " + scidValue);
								packetInfo.setSCID(scidValue);
							}
							//outFile.writeToFile(packetInfo);
							conn.clientToServerPackets.add(packetInfo);
						} else {
							Connection conn = connections.get(sourceIP + destinationIP);
							if (conn == null) {
								conn = connections.get(destinationIP + sourceIP);
							}
							System.out.println("Client is : " + conn.getClientIP());
							System.out.println("Server is : " + conn.getServerIP());
							if (conn.clientIP.equals(sourceIP)) {
								conn.clientToServerPackets.add(packetInfo);
							} else {
								if (chloTag.equals("52454A00")) {
									System.out.println("Rejection packet!!");
									packetInfo.setRej(true);
								}
								//outFile.writeToFile(packetInfo);
								conn.serverToClientPackets.add(packetInfo);
							}
						}
					} else {
						Connection conn = connections.get(sourceIP + destinationIP);
						if (conn == null) {
							conn = connections.get(destinationIP + sourceIP);
						}
						System.out.println("Client is : " + conn.getClientIP());
						System.out.println("Server is : " + conn.getServerIP());
						if (conn.clientIP.equals(sourceIP)) {
							conn.clientToServerPackets.add(packetInfo);
						} else {
							conn.serverToClientPackets.add(packetInfo);
						}
						//outFile.writeToFile(packetInfo);
					}
					outFile.writeToFile(packetInfo);
					packetsInfo.add(packetInfo);
					System.out.println("###########################");
				}

			}
		}
		System.out.println("number of quic packets = " + packetsInfo.size());
		Connection conn = connections.get("10.0.2.15216.58.217.164");
		List<PacketInfo> connPackets = conn.getClientToServerPackets();
		System.out.println("number of client to server packets : " + connPackets.size());
		System.out.println("number of server to client packets : " + conn.getServerToClientPackets().size());
		for (int i = 0; i < connPackets.size(); i++) {
			System.out.println("Frame no. is : " + connPackets.get(i).frameNo);
		}
		
		long lastPacketTime = 0;
		boolean reconnFlag = false;
		boolean handshakeFlag = false;
		int chloHandshake = 0;
		int handshakeCount = 0;
		int reconnCount = 0;
		for(PacketInfo pkt : packetsInfo){
			outFile.writeToFile(pkt);
			if(handshakeFlag && !reconnFlag){
				outFile_handshake.writeToFile(pkt);
			}
			if(reconnFlag){
				outFile_reconnection.writeToFile(pkt);
			}
			if(!handshakeFlag){
				if(pkt.isChlo){
					if(pkt.getSCID()==null){
						outFile_handshake.writeToFile(pkt);
						chloHandshake++;
						handshakeCount++;
					}
					else if(chloHandshake==1 && pkt.getSCID()!= null){
						outFile_handshake.writeToFile(pkt);
						chloHandshake++;
						handshakeCount++;
						handshakeFlag = true;
					}
				}
				if(pkt.isRej){
					if(chloHandshake==1){
						outFile_handshake.writeToFile(pkt);
						handshakeCount++;
					}
				}
			}
			if(!reconnFlag){
				if(pkt.isChlo){
					if(pkt.getSCID()!=null && pkt.getTimeStamp()-lastPacketTime > 30000){
						outFile_reconnection.writeToFile(pkt);
						reconnFlag = true;
						reconnCount++;
					}
				}
			}		
			lastPacketTime = pkt.getTimeStamp();
		}

	}

	public static int getBit(int position, byte ID) {
		return (ID >> position) & 1;
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

	private static long getDetails(PcapPacket packet, int index1, int index2) {
		String attributeStr = getBytesToHexString(packet, index1, index2);
		if (attributeStr.length() >= 8) {
			BigInteger big = new BigInteger(attributeStr, 16);
			System.out.println("BigInteger is: " + big);
			System.out.println("cid hex string is : " + attributeStr);
		}
		long attributeInt = hex2decimal(attributeStr);
		return attributeInt;
	}

	private static String getTags(PcapPacket packet, int index1, int index2) throws UnsupportedEncodingException {
		String attributeStr = getBytesToHexString(packet, index1, index2);
		System.out.println("In get Tag value is : " + attributeStr);
		// String attributeInt = hexToString(attributeStr);
		return attributeStr;
	}

	private static String getBytesToHexString(PcapPacket packet, int index1, int index2) {
		byte[] label = new byte[index2 - index1 + 1];
		for (int i = index1; i <= index2; i++) {
			label[i - index1] = packet.getByte(i);
		}

		StringBuilder labelHex = new StringBuilder();
		for (byte b : label) {
			labelHex.append(String.format("%02X ", b));
		}
		String labelString = labelHex.toString();
		labelString = labelString.replaceAll("\\s", "");
		return labelString;
	}

	public static String hexToString(String tag) throws UnsupportedEncodingException {
		tag = tag.toUpperCase();

		String[] list = tag.split("(?<=\\G.{2})");
		ByteBuffer buffer = ByteBuffer.allocate(list.length);
		for (String str : list)
			buffer.put(Byte.parseByte(str, 16));
		String convertedString = new String(buffer.array(), "UTF-8");
		System.out.println("Tag is : " + convertedString);
		return convertedString;
	}

	public static long hex2decimal(String s) {
		String digits = "0123456789ABCDEF";
		s = s.toUpperCase();
		long val = 0;
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			int d = digits.indexOf(c);
			val = 16 * val + d;
		}
		return val;
	}
}
