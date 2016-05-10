import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.util.PcapPacketArrayList;

/*
 * The helper class. Contains methods that are used to extract bit level data from QUIC, HTTP or SPDY packets.
 */
public class ParserHelper {
	
	// method to get a bit value from a given byte
	public static int getBit(int position, byte ID) {
		return (ID >> position) & 1;
	}

	// method to get array of packets from read pcap file.
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

	// method to get decimal value of a tag
	public static long getDetails(PcapPacket packet, int index1, int index2) {
		String attributeStr = getBytesToHexString(packet, index1, index2);
		long attributeInt = hex2decimal(attributeStr);
		return attributeInt;
	}

	// method to convert bytes to hexa-decimal
	public static String getBytesToHexString(PcapPacket packet, int index1, int index2) {
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

	// method to convert hexa-decimal to decimal value.
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
