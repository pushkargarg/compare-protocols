import java.util.ArrayList;
import java.util.List;

/*
 * Class to store connections and corresponding client and server packets.
 */
public class Connection {

	String id;
	String clientIP;
	String serverIP;
	List<PacketInfo> clientToServerPackets = new ArrayList<PacketInfo>();
	List<PacketInfo> serverToClientPackets = new ArrayList<PacketInfo>();
	public String getId() {
		return id;
	}
	public void setId(String id) {
		this.id = id;
	}
	public String getClientIP() {
		return clientIP;
	}
	public void setClientIP(String clientIP) {
		this.clientIP = clientIP;
	}
	public String getServerIP() {
		return serverIP;
	}
	public void setServerIP(String serverIP) {
		this.serverIP = serverIP;
	}
	public List<PacketInfo> getClientToServerPackets() {
		return clientToServerPackets;
	}
	public void setClientToServerPackets(List<PacketInfo> clientToServerPackets) {
		this.clientToServerPackets = clientToServerPackets;
	}
	public List<PacketInfo> getServerToClientPackets() {
		return serverToClientPackets;
	}
	public void setServerToClientPackets(List<PacketInfo> serverToClientPackets) {
		this.serverToClientPackets = serverToClientPackets;
	}
	
	
}
