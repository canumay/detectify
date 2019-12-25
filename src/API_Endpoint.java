
import java.util.HashMap;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
/**
 *
 * @author Can Umay
 */
public abstract class API_Endpoint {
    private static final String FILE_URL = "https://www.virustotal.com/vtapi/v2/file/report";
    private static final String DOMAIN_URL = "https://www.virustotal.com/vtapi/v2/url/report";

    public static String getFILE_URL() {
        return FILE_URL;
    }

    public static String getDOMAIN_URL() {
        return DOMAIN_URL;
    }

    public static String getAPI_KEY() {
        DatabaseOperations db = new DatabaseOperations();
        return db.getAPIKey();
    }

    abstract String get(HashMap<String, String> params, boolean isFile);

    abstract String post(String fileDirectory); 
}
