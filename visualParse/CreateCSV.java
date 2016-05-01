package visualParse;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import com.opencsv.*;

public class CreateCSV {
	String fileName;
	private int columnCount = 0;
	public CreateCSV(String filename) {
		this.fileName = filename;
		File f = new File(this.fileName);
		if(f.exists())
		{
			f.delete();
		}
	}

	public void writeToFile(ParsePacketInfo packet)
	{
		boolean exists = new File(this.fileName).exists();
		try {
			CSVWriter csvOutput = new CSVWriter(new FileWriter(this.fileName, true), ',');
			if (!exists) {
				//For headings
				this.columnCount = packet.getHeaderString().split(",").length;
				csvOutput.writeNext(packet.getHeaderString().split(","));
			}
			csvOutput.writeNext(packet.getAllString().split(","));
			csvOutput.close();
		} catch (IOException e) {
			System.out.println("Problem in writing");
		}
	}
	public void insertEmpty()
	{
		String empty[] = new String[this.columnCount];
		for(int i = 0; i < this.columnCount; i++)
		{
			empty[i] = "NULL";
		}
		CSVWriter csvOutput;
		try {
			csvOutput = new CSVWriter(new FileWriter(this.fileName, true), ',');
			csvOutput.writeNext(empty);
			csvOutput.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}
