
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.awt.AWTException;
import java.util.ArrayList;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
/**
 *
 * @author Can Umay
 */
public class AntivirusParser {

    private static ArrayList<Antivirus> results;
    private String md5;
    private String sha1;
    private String sha256;
    private String scanDate;
    private int total;
    private int positives;
    private boolean isFile;
    private JsonObject jsonObject;
    public boolean isScanSuccess = false;
    public String scanResponse;
    public boolean isParseSuccess = false;
    public String scanId;
    public String permaLink;

    public AntivirusParser(String result, boolean isFile) throws AWTException {
        this.results = new ArrayList();
        this.isFile = isFile;
        JsonParser jsonParser = new JsonParser();
        try {
            JsonElement jsonTree = jsonParser.parse(result);
            if (!"null".equals(jsonTree.toString())) {
                if (jsonTree.isJsonObject()) {
                    JsonObject jObject = jsonTree.getAsJsonObject();
                    this.jsonObject = jObject;
                    String verbose_msg = jsonObject.get("verbose_msg").getAsString();
                    this.scanResponse = verbose_msg;
                    if (verbose_msg.equals("Scan finished, scan information embedded in this object") || verbose_msg.equals("Scan finished, information embedded")) {
                        this.isScanSuccess = true;
                        parseResults();
                    } else if (verbose_msg.equals("Scan request successfully queued, come back later for the report")) {
                        this.scanId = jsonObject.get("scan_id").getAsString();

                    }
                    if (!this.isScanSuccess) {
                        Notify.displayTray(scanResponse, "warning");
                    }
                }
            } else {
                Notify.displayTray("You exceeded scan limit, please try again later.", "error");
            }
        } catch (java.lang.NullPointerException e) {
            Notify.displayTray("Looks like API key is not correct, please check it.", "error");
        }

    }

    public void parseResults() throws AWTException {
        if (this.isScanSuccess) {
            if (isFile) {
                this.md5 = jsonObject.get("md5").toString();
                this.sha1 = jsonObject.get("sha1").toString();
                this.sha256 = jsonObject.get("sha256").toString();
            }
            this.scanDate = jsonObject.get("scan_date").toString();
            this.total = Integer.parseInt(jsonObject.get("total").toString());
            this.positives = Integer.parseInt(jsonObject.get("positives").toString());
            this.permaLink = jsonObject.get("permalink").toString();
            String fileType = this.isFile == true ? "file" : "url";
            if (this.positives > 0) {
                Notify.displayTray(String.format("Warning, %d malware detected on that %s!", this.positives, fileType), "error");
            } else {
                Notify.displayTray(String.format("No malware detected on that %s!", fileType), "info");
            }
            this.scanId = jsonObject.get("scan_id").getAsString();
            JsonObject scans = jsonObject.get("scans").getAsJsonObject();
            for (String key : scans.keySet()) {
                Antivirus temp = new Antivirus(scans.get(key).getAsJsonObject(), key);
                this.results.add(temp);
            }
            this.isParseSuccess = true;
        } else {
            Notify.displayTray("Scan is not successful, please scan later.", "error");
        }

    }

    @Override
    public String toString() {
        String output = "";
        for (int i = 0; i < this.total; i++) {
            output += this.results.get(i).toString() + "\n";
        }
        return output;
    }
    
    public String getPermaLink(){
        return permaLink;
    }

    public String getMd5() {
        return md5;
    }

    public String getSha1() {
        return sha1;
    }

    public ArrayList<Antivirus> getResults() {
        return results;
    }

    public void setResults(ArrayList<Antivirus> results) {
        this.results = results;
    }

    public String getSha256() {
        return sha256;
    }

    public String getScanDate() {
        return scanDate;
    }

    public int getTotal() {
        return total;
    }

    public int getPositives() {
        return positives;
    }

}
