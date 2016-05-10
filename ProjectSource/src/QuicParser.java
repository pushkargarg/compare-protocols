import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.jnetpcap.packet.Payload;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.util.PcapPacketArrayList;

/*
 * The QUIC Parser. Takes pcap file name as input argument and creates three CSV files for handshake, reconnection and full flow containing information such as 
 * source and destination IP addresses, port numbers, sequence number, Connection ID. Also identifies if packet is client hello or server rejection and in either 
 * case extracts server configurations if present.
 */
public class QuicParser {

	public static String outFileName_handshake;
	public static String outFileName_reconnection;
	public static String outFileName;

	public static void main(String args[]) throws UnsupportedEncodingException {

		if (args.length < 1) {
			System.out.println("Pcap File name not specified!!");
			System.exit(0);
		}

		String FILENAME = args[0];
		outFileName_handshake = FILENAME + "_handshake.csv";
		outFileName_reconnection = FILENAME + "_reconnection.csv";
		outFileName = FILENAME + ".csv";

		CreateCSV outFile = new CreateCSV(outFileName);
		CreateCSV outFile_handshake = new CreateCSV(outFileName_handshake);
		CreateCSV outFile_reconnection = new CreateCSV(outFileName_reconnection);

		boolean threshold = false;
		long totalPacketSize = 0;
		long endPacketTm = 0;
		double throughput;

		int counter = 0;
		long timeDiff = 0;
		Set<String> clients = new HashSet<String>();
		Set<String> servers = new HashSet<String>();
		Map<String, Connection> connections = new HashMap<String, Connection>();
		List<PacketInfo> packetsInfo = new ArrayList<PacketInfo>();
		PcapPacketArrayList packets = ParserHelper.readOfflineFiles(FILENAME);
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
					PacketInfo packetInfo = new PacketInfo();

					// get payload content
					packet.getHeader(pl);
					byte[] payloadContent = pl.getByteArray(0, pl.size());
					String strPayloadContent = new String(payloadContent);

					if (packet.hasHeader(ip)) {
						sourceIP = FormatUtils.ip(packet.getHeader(ip).source());
						destinationIP = FormatUtils.ip(packet.getHeader(ip).destination());
					}

					long timeStamp = packet.getCaptureHeader().timestampInMillis();
					System.out.println("Timestamp is : " + timeStamp);

					if (counter == 0) {
						timeDiff = timeStamp;
						timeStamp = 0;
						counter++;
					} else {
						timeStamp -= timeDiff;
					}

					// setting up threshold to ignore reconnection packets
					if (timeStamp - endPacketTm > 10000) {
						threshold = true;
					}

					if (!threshold) {
						totalPacketSize += packet.size();
						endPacketTm = timeStamp;
					}

					Byte publicFlag = packet.getByte(42);
					int versionBit = ParserHelper.getBit(0, publicFlag);

					// get size of CID
					String cidSizeStr = "";
					for (int i = 2; i < 4; i++) {
						int cidBit = ParserHelper.getBit(i, publicFlag);
						cidSizeStr = cidSizeStr + Integer.toString(cidBit);
					}

					int cidLength = 0;
					if (cidSizeStr.equals("11")) {
						cidLength = 8;
					} else if (cidSizeStr.equals("10")) {
						cidLength = 4;
					} else if (cidSizeStr.equals("01")) {
						cidLength = 1;
					} else {
						cidLength = 0;
					}

					// get Connection ID value
					String cid = null;
					if (cidLength != 0) {
						cid = ParserHelper.getBytesToHexString(packet, 43, 43 + cidLength - 1);
						System.out.println("CID is : " + cid);
					}

					// get Sequence number size
					String seqSizeStr = "";
					for (int i = 4; i < 6; i++) {
						int seqBit = ParserHelper.getBit(i, publicFlag);
						seqSizeStr = seqSizeStr + Integer.toString(seqBit);
					}
					System.out.println("SEQ bits are: " + seqSizeStr);

					int seqLength = 0;
					if (seqSizeStr.equals("00")) {
						seqLength = 1;
					} else if (seqSizeStr.equals("01")) {
						seqLength = 2;
					} else if (seqSizeStr.equals("11")) {
						seqLength = 6;
					} else if (seqSizeStr.equals("10")) {
						seqLength = 4;
					}

					// get sequence number value start index
					int seqStart = 0;
					if (versionBit == 1) {
						seqStart = 43 + cidLength + 4;
					} else {
						seqStart = 43 + cidLength;
					}

					// get Sequence number
					long seqNo = ParserHelper.getDetails(packet, seqStart, seqStart + seqLength - 1);

					// set information in PacketInfo
					packetInfo.setFrameNo(packet.getFrameNumber());
					packetInfo.setDstPort(dstPort);
					packetInfo.setSrcPort(srcPort);
					packetInfo.setDestinationIP(destinationIP);
					packetInfo.setSourceIP(sourceIP);
					packetInfo.setTimeStamp(timeStamp);
					packetInfo.setCid(cid);
					packetInfo.setSeqNo(seqNo);

					// get frames information
					int messageAuthenticationPosition = seqStart + seqLength + 1;
					int messageAuthLength = 12;
					int frameStart = messageAuthenticationPosition + messageAuthLength;
					Byte frameFlag = packet.getByte(frameStart);
					String frameFlags = Integer.toBinaryString(frameFlag);

					String frameType = "none";
					int streamFrameStart = 0;
					if (strPayloadContent.contains("CHLO") || strPayloadContent.contains("REJ")) {

						// loop to get to STREAM Frame start index
						while (!frameType.equals("Stream")) {
							int frameTypeBit1 = ParserHelper.getBit(7, frameFlag);
							int frameTypeBit2 = ParserHelper.getBit(6, frameFlag);
							if (frameTypeBit1 == 1) {
								frameType = "Stream";
								streamFrameStart = frameStart;
								continue;
							} else if (frameTypeBit1 == 0 && frameTypeBit2 == 1) {
								frameType = "Ack";
								int frameSize = 10;
								int largestObsBit1 = ParserHelper.getBit(3, frameFlag);
								int largestObsBit2 = ParserHelper.getBit(2, frameFlag);
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
								frameSize += largestObsSize;
								int nackBit = ParserHelper.getBit(5, frameFlag);
								if (nackBit == 1) {
									frameSize += 2;
								}

								frameStart += frameSize;
								frameFlag = packet.getByte(frameStart);
								frameFlags = Integer.toBinaryString(frameFlag);
								continue;
							} else if (frameFlags.equals("110")) {
								frameType = "Stop_Waiting";
								frameStart = frameStart + 2 + seqLength;
								frameFlag = packet.getByte(frameStart);
								frameFlags = Integer.toBinaryString(frameFlag);
								continue;
							}
						}
					}

					// get starting index for CHLO or REJ Tag
					int chloTagStart = streamFrameStart;
					int offsetBit1 = ParserHelper.getBit(4, frameFlag);
					int offsetBit2 = ParserHelper.getBit(3, frameFlag);
					int offsetBit3 = ParserHelper.getBit(2, frameFlag);
					int dataLengthBit = ParserHelper.getBit(5, frameFlag);
					if (dataLengthBit == 1) {
						chloTagStart += 2;
					}
					String offsetBits = Integer.toString(offsetBit1) + Integer.toString(offsetBit2)
							+ Integer.toString(offsetBit3);
					if (offsetBits.equals("000")) {
						chloTagStart += 0;
					} else if (offsetBits.equals("001")) {
						chloTagStart += 2;
					} else if (offsetBits.equals("010")) {
						chloTagStart += 3;
					} else if (offsetBits.equals("100")) {
						chloTagStart += 4;
					} else if (offsetBits.equals("110")) {
						chloTagStart += 5;
					} else if (offsetBits.equals("101")) {
						chloTagStart += 6;
					} else if (offsetBits.equals("011")) {
						chloTagStart += 7;
					} else if (offsetBits.equals("111")) {
						chloTagStart += 8;
					}
					if (offsetBit1 == 0) {
						chloTagStart += 1;
					}
					int streamIDBit1 = ParserHelper.getBit(1, frameFlag);
					int streamIDBit2 = ParserHelper.getBit(0, frameFlag);
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
					if (packet.getCaptureHeader().hdr_len() > (chloTagStart + 4)) {
						String chloTag = ParserHelper.getBytesToHexString(packet, chloTagStart, chloTagStart + 3);
						if (chloTag.equals("43484C4F")) {

							// create client to server packet
							clients.add(sourceIP);
							servers.add(destinationIP);
							packetInfo.setChlo(true);
							Connection conn = connections.get(sourceIP + destinationIP);
							if (conn == null) {
								conn = new Connection();
								conn.setId(sourceIP + destinationIP);
								conn.setClientIP(sourceIP);
								conn.setServerIP(destinationIP);
								connections.put(conn.getId(), conn);
							}

							// get Server Configuration ID tag and Value
							long tagNo = ParserHelper.getDetails(packet, chloTagStart + 4, chloTagStart + 4);
							int tagsStart = chloTagStart + 8;
							int SCIDoffSet = 0;
							for (int ti = 0; ti < tagNo; ti++) {
								String type = ParserHelper.getBytesToHexString(packet, tagsStart, tagsStart + 3);
								if (type.equals("53434944")) {
									SCIDoffSet = (int) ParserHelper.getDetails(packet, tagsStart + 5, tagsStart + 5);
									SCIDoffSet = SCIDoffSet << 8;
									SCIDoffSet += (int) ParserHelper.getDetails(packet, tagsStart + 4, tagsStart + 4);
								}
								tagsStart += 8;
							}
							if (SCIDoffSet != 0) {
								int SCIDvalue = tagsStart + SCIDoffSet - 16;
								String scidValue = ParserHelper.getBytesToHexString(packet, SCIDvalue, SCIDvalue + 15);
								packetInfo.setSCID(scidValue);
							}

							conn.clientToServerPackets.add(packetInfo);
						} else {
							Connection conn = connections.get(sourceIP + destinationIP);
							if (conn == null) {
								conn = connections.get(destinationIP + sourceIP);
							}
							if (conn.clientIP.equals(sourceIP)) {
								conn.clientToServerPackets.add(packetInfo);
							} else {

								// get SCID location and value in Server REJ
								// packet
								if (chloTag.equals("52454A00")) {
									int scfgLoc = (strPayloadContent.indexOf("SCFG") + 42);
									scfgLoc = (strPayloadContent.indexOf("SCFG", (scfgLoc + 1)) + 42);
									int scidLoc = (strPayloadContent.indexOf("SCID") + 42);
									int numSerCfgTag = (int) ParserHelper.getDetails(packet, scfgLoc + 4, scfgLoc + 4);
									int offSet = (int) ParserHelper.getDetails(packet, scidLoc + 5, scidLoc + 5);
									offSet = offSet << 8;
									offSet += ParserHelper.getDetails(packet, scidLoc + 4, scidLoc + 4);
									int targetLoc = ((scfgLoc + (numSerCfgTag + 1) * 8) + offSet);
									String scidVal = ParserHelper.getBytesToHexString(packet, targetLoc - 16,
											targetLoc - 1);
									packetInfo.setSCID(scidVal);
									packetInfo.setRej(true);
								}
								conn.serverToClientPackets.add(packetInfo);
							}
						}
					} else {
						Connection conn = connections.get(sourceIP + destinationIP);
						if (conn == null) {
							conn = connections.get(destinationIP + sourceIP);
						}
						if (conn.clientIP.equals(sourceIP)) {
							conn.clientToServerPackets.add(packetInfo);
						} else {
							conn.serverToClientPackets.add(packetInfo);
						}
					}
					outFile.writeToFile(packetInfo);
					packetsInfo.add(packetInfo);
				}

			}
		}

		// calculate throughput and page load time
		throughput = totalPacketSize / endPacketTm;
		System.out.println("Pageload time = " + endPacketTm/1000);
		System.out.println("Throughput is : " + throughput * 1000 + " bytes per sec");

		// segregate handshake and reconnection packets
		long lastPacketTime = 0;
		boolean reconnFlag = false;
		boolean handshakeFlag = false;
		int chloHandshake = 0;
		for (PacketInfo pkt : packetsInfo) {
			outFile.writeToFile(pkt);
			if (handshakeFlag && !reconnFlag) {
				outFile_handshake.writeToFile(pkt);
			}
			if (reconnFlag) {
				outFile_reconnection.writeToFile(pkt);
			}
			if (!handshakeFlag) {
				if (pkt.isChlo) {
					if (pkt.getSCID() == null) {
						outFile_handshake.writeToFile(pkt);
						chloHandshake++;

					} else if (chloHandshake == 1 && pkt.getSCID() != null) {
						outFile_handshake.writeToFile(pkt);
						chloHandshake++;

						handshakeFlag = true;
					}
				}
				if (pkt.isRej) {
					if (chloHandshake == 1) {
						outFile_handshake.writeToFile(pkt);

					}
				}
			}
			if (!reconnFlag) {
				if (pkt.isChlo) {
					if (pkt.getSCID() != null && pkt.getTimeStamp() - lastPacketTime > 30000) {
						outFile_reconnection.writeToFile(pkt);
						reconnFlag = true;

					}
				}
			}
			lastPacketTime = pkt.getTimeStamp();
		}

	}
}
