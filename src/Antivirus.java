
import com.google.gson.JsonObject;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
/**
 *
 * @author Can Umay
 */
public class Antivirus {

    private String name;
    private boolean detected;
    private String version;
    private String result;

    public Antivirus(JsonObject result, String name) {
        this.name = name;
        this.detected = Boolean.parseBoolean(result.get("detected").toString());
        // Domain tarama bu özelliğe sahip değil.
        if (result.get("version") != null) {
            this.version = result.get("version").toString();
        }
        this.result = result.get("result").toString();
    }

    public String getName() {
        return name;
    }

    public boolean isDetected() {
        return detected;
    }

    public String getVersion() {
        return version;
    }

    public String getResult() {
        return result;
    }

    @Override
    public String toString() {
        return "Antivirus{" + "name=" + name + ", detected=" + detected + ", version=" + version + ", result=" + result + '}';
    }

}
