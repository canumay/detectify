
import java.sql.Connection;
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
public interface Database {
    public abstract Connection connect();
    public abstract void insert(String name, String scan_id, String type, String fileName, String fileSize, String fileExtension);
    public abstract void update(String apiKey);
    public abstract void delete(String scan_id);
    public abstract ArrayList select();
    public abstract ArrayList select(String scan_id);
}
