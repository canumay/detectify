
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
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
public class DatabaseOperations implements Database {

    @Override
    public void insert(String name, String scan_id, String type, String fileName, String fileSize, String fileExtension) {
        String sql = "INSERT INTO results(name, scan_id, type, file_name, file_size, file_extension) VALUES(?,?,?,?,?,?)";
        try (Connection conn = this.connect();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, name);
            pstmt.setString(2, scan_id);
            pstmt.setString(3, type);
            pstmt.setString(4, fileName);
            pstmt.setString(5, fileSize);
            pstmt.setString(6, fileExtension);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    @Override
    public void update(String apiKey) {
        String sql = "UPDATE settings SET api_key = ? WHERE id=1";
        try (Connection conn = this.connect();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, apiKey);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    @Override
    public void delete(String id) {
        String sql = "DELETE FROM results WHERE id = ?";

        try (Connection conn = this.connect();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {

            // set the corresponding param
            pstmt.setString(1, id);
            // execute the delete statement
            pstmt.executeUpdate();

        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    @Override
    public ArrayList select() {
        ArrayList<HashMap> results = new ArrayList();
        String sql = "SELECT id, name, scan_id, type, scan_date FROM results";

        try (Connection conn = this.connect();
                Statement stmt = conn.createStatement();
                ResultSet rs = stmt.executeQuery(sql)) {

            // loop through the result set
            while (rs.next()) {
                HashMap<String, String> res = new HashMap();
                res.put("id", rs.getString("id"));
                res.put("name", rs.getString("name"));
                res.put("scan_id", rs.getString("scan_id"));
                res.put("scan_date", rs.getString("scan_date"));
                res.put("type", rs.getString("type"));
                results.add(res);
            }
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
        return results;
    }

    @Override
    public ArrayList select(String scan_id) {
        ArrayList results = new ArrayList();
        String sql = "SELECT name, file_name, file_size, file_extension FROM results WHERE scan_id = ?";
        try (Connection conn = this.connect();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {

            // set the value
            pstmt.setString(1, scan_id);
            //
            ResultSet rs = pstmt.executeQuery();

            // loop through the result set
            while (rs.next()) {
                HashMap<String, String> temp = new HashMap();
                temp.put("name", rs.getString("name"));
                temp.put("file_name", rs.getString("file_name"));
                temp.put("file_size", rs.getString("file_size"));
                temp.put("file_extension", rs.getString("file_extension"));
                results.add(temp);
            }
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
        return results;
    }

    @Override
    public Connection connect() {
        String url = "jdbc:sqlite:db/detectify.db";
        Connection conn = null;
        try {
            conn = DriverManager.getConnection(url);
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
        return conn;
    }

    public void initResultTable() {
        String sql = "CREATE TABLE IF NOT EXISTS results (\n"
                + "    id integer PRIMARY KEY,\n"
                + "    name text NOT NULL,\n"
                + "    scan_id text NOT NULL,\n"
                + "    type text NOT NULL,\n"
                + "    file_name text,\n"
                + "    file_size text,\n"
                + "    file_extension text,\n"
                + "    scan_date DEFAULT CURRENT_TIMESTAMP\n"
                + ");";

        try (Connection conn = this.connect();
                Statement stmt = conn.createStatement()) {
            stmt.execute(sql);
            System.out.println("Table initalization for Result Table is successfull");

        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    public void initAPIKeyTable() {
        String sql = "CREATE TABLE IF NOT EXISTS settings (\n"
                + "    id integer PRIMARY KEY,\n"
                + "    api_key text NOT NULL\n"
                + ");";

        try (Connection conn = this.connect();
                Statement stmt = conn.createStatement()) {
            stmt.execute(sql);
            System.out.println("Table initalization for API Key is successfull");
            sql = "INSERT OR IGNORE INTO settings(id,api_key) VALUES(1,?);";
            try (Connection conn2 = this.connect();
                    PreparedStatement pstmt = conn.prepareStatement(sql)) {
                pstmt.setString(1, "api-key-not-defined");
                pstmt.executeUpdate();
            } catch (SQLException e) {
                System.out.println(e.getMessage());
            }
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    public String getAPIKey() {
        String sql = "SELECT api_key FROM settings WHERE id = 1;";
        String apiKey = null;

        try (Connection conn = this.connect();
                Statement stmt = conn.createStatement();
                ResultSet rs = stmt.executeQuery(sql)) {

            // loop through the result set
            while (rs.next()) {
                apiKey = rs.getString("api_key");
            }
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
        return apiKey;
    }

    public int getTotalCount() {
        String sql = "SELECT COUNT(*) AS total FROM results";
        int count = -1;
        try (Connection conn = this.connect();
                Statement stmt = conn.createStatement();
                ResultSet rs = stmt.executeQuery(sql)) {

            count = rs.getInt("total");
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
        return count;
    }

    public int getFileCount() {
        String sql = "SELECT COUNT(*) AS total FROM results WHERE type='file'";
        int count = -1;
        try (Connection conn = this.connect();
                Statement stmt = conn.createStatement();
                ResultSet rs = stmt.executeQuery(sql)) {

            count = rs.getInt("total");
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
        return count;
    }

    public int getURLCount() {
        String sql = "SELECT COUNT(*) AS total FROM results WHERE type='url'";
        int count = -1;
        try (Connection conn = this.connect();
                Statement stmt = conn.createStatement();
                ResultSet rs = stmt.executeQuery(sql)) {

            count = rs.getInt("total");
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
        return count;
    }

}
