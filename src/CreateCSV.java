import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import com.opencsv.*;

public class CreateCSV {
	String fileName;

	public CreateCSV(String filename) {
		this.fileName = filename;
	}

	public void writeToFile(ParsePacketInfo packet)
	{
		boolean exists = new File(this.fileName).exists();
		try {
			CSVWriter csvOutput = new CSVWriter(new FileWriter(this.fileName, true), ',');
			if (!exists) {
				//For headings
				csvOutput.writeNext(packet.getHeaderString().split(","));
			}
			csvOutput.writeNext(packet.getAllString().split(","));
			csvOutput.close();
		} catch (IOException e) {
			System.out.println("Problem in writing");
		}
	}
	

}
