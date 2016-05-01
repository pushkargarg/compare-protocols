package visualParse;


public class PacketInfo implements ParsePacketInfo {
	
	long frameNo;
	long dstPort;
	long srcPort;
	String destinationIP;
	String sourceIP;
	long timeStamp;
	String cid;
	long seqNo;
	boolean isChlo;
	boolean isRej;
	String SCID;
	
	public long getFrameNo() {
		return frameNo;
	}
	public void setFrameNo(long frameNo) {
		this.frameNo = frameNo;
	}
	public long getDstPort() {
		return dstPort;
	}
	public void setDstPort(long dstPort) {
		this.dstPort = dstPort;
	}
	public long getSrcPort() {
		return srcPort;
	}
	public void setSrcPort(long srcPort) {
		this.srcPort = srcPort;
	}
	public String getDestinationIP() {
		return destinationIP;
	}
	public void setDestinationIP(String destinationIP) {
		this.destinationIP = destinationIP;
	}
	public String getSourceIP() {
		return sourceIP;
	}
	public void setSourceIP(String sourceIP) {
		this.sourceIP = sourceIP;
	}
	public long getTimeStamp() {
		return timeStamp;
	}
	public void setTimeStamp(long timeStamp) {
		this.timeStamp = timeStamp;
	}
	public String getCid() {
		return cid;
	}
	public void setCid(String cid) {
		this.cid = cid;
	}
	public long getSeqNo() {
		return seqNo;
	}
	public void setSeqNo(long seqNo) {
		this.seqNo = seqNo;
	}
	public boolean isChlo() {
		return isChlo;
	}
	public void setChlo(boolean isChlo) {
		this.isChlo = isChlo;
	}
	public boolean isRej() {
		return isRej;
	}
	public void setRej(boolean isRej) {
		this.isRej = isRej;
	}
	public String getSCID() {
		return SCID;
	}
	public void setSCID(String sCID) {
		SCID = sCID;
	}
	public String getHeaderString() {
		return "frame,dstport,srcport,destIP,srcIP,timestamp,cid,seqNo,isChlo,isRej,SCID";
	}
	public String getAllString(){
		//return String.format("%s", this.frameNo);
		return String.format("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s", this.frameNo,this.dstPort,this.srcPort
				,this.destinationIP,this.sourceIP,this.timeStamp,this.cid,this.seqNo,this.isChlo,this.isRej,this.SCID);
		
	}
}
