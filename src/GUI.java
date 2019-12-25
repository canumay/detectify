
import java.awt.AWTException;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.Desktop;
import java.awt.GridLayout;
import java.awt.Image;
import java.awt.Point;
import java.awt.Toolkit;
import java.util.List;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.BorderFactory;
import javax.swing.Icon;
import javax.swing.ImageIcon;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.TransferHandler;
import javax.swing.border.Border;
import javax.swing.table.DefaultTableModel;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
/**
 *
 * @author QP Pulse Plus
 */
public class GUI extends javax.swing.JFrame {
    String currentReportURL;
    
    @Override
    public synchronized void setIconImages(List<? extends Image> icons) {
        super.setIconImages(icons);
    }

    @Override
    public void setIconImage(Image image) {
        super.setIconImage(image);
    }

    public static boolean openWebpage(URI uri) {
        Desktop desktop = Desktop.isDesktopSupported() ? Desktop.getDesktop() : null;
        if (desktop != null && desktop.isSupported(Desktop.Action.BROWSE)) {
            try {
                desktop.browse(uri);
                return true;
            } catch (IOException e) {
            }
        }
        return false;
    }

    public static boolean openWebpage(URL url) {
        try {
            return openWebpage(url.toURI());
        } catch (URISyntaxException e) {
        }
        return false;
    }

    int x, y, leftCord;
    public static DateTimeFormatter format = DateTimeFormatter.ofPattern("HH:mm:ss");

    public void getAPIKey() {
        this.apiKeyText.setText(this.detectifyDB.getAPIKey());
    }

    public void updateAPIKey() {
        this.detectifyDB.update(this.apiKeyText.getText());
        this.getAPIKey();
    }
    
    public void setCurrentReportURL(String permaLink){
        this.currentReportURL = permaLink;
    }

    public void getScannedFiles() {
        DefaultTableModel model = (DefaultTableModel) jTable1.getModel();
        ArrayList<HashMap> myList = detectifyDB.select();
        Object[] row = new Object[7];
        if (model.getRowCount() > 0) {
            for (int l = model.getRowCount() - 1; l > -1; l--) {
                model.removeRow(l);
            }
        }
        for (int Q = 0; Q < myList.size(); Q++) {
            row[0] = myList.get(Q).get("id");
            row[1] = myList.get(Q).get("name");
            row[2] = myList.get(Q).get("type");
            row[3] = myList.get(Q).get("scan_id");
            row[4] = myList.get(Q).get("scan_date");
            row[5] = "Delete";
            row[6] = "Detail";
            model.addRow(row);
        }

    }

    public void urlScan(String url, boolean save) throws AWTException {
        HashMap<String, String> params = new HashMap<>();
        params.put("url", url);
        MalwareChecker checker = new MalwareChecker();
        String content = checker.get(params, false);
        AntivirusParser parser = new AntivirusParser(content, false);
        if (parser.scanResponse != null) {
            if (parser.isScanSuccess) {
                this.setCurrentReportURL(parser.getPermaLink());
                if (save) {
                    this.detectifyDB.insert(url, parser.scanId, "url", null, null, null);
                }
                ArrayList results = this.detectifyDB.select(parser.scanId);
                HashMap<String, String> result = (HashMap) results.get(0);
                FileNameLabel.setText(result.get("name"));
                SizeLabel.setText("");
                ExtensionLabel.setText("");
                SizeLabel.setVisible(false);
                jLabel38.setVisible(false);
                jLabel41.setVisible(false);
                jLabel40.setVisible(false);
                jLabel12.setVisible(false);
                ExtensionLabel.setVisible(false);
                FileTypeLabel.setVisible(false);
                HashLabel.setText(parser.scanId);
                if (parser.getPositives() == 0) {
                    StatusLabel.setForeground(new Color(0, 102, 0));
                    TotalCount.setForeground(new Color(0, 102, 0));
                    Border border = BorderFactory.createLineBorder(new Color(0, 102, 0));
                    jPanel3.setBorder(border);
                    jLabel37.setForeground(new Color(0, 102, 0));
                    StatusLabel.setText("No malware detected on this URL!");
                    jLabel42.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/icons8-checkmark-15.png")));
                } else {
                    TotalCount.setForeground(Color.red);
                    Border border = BorderFactory.createLineBorder(Color.red);
                    jPanel3.setBorder(border);
                    jLabel37.setForeground(Color.red);
                    StatusLabel.setForeground(Color.red);
                    StatusLabel.setText(String.format("%d engines detected on this URL", parser.getPositives()));
                    jLabel42.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/icons8-delete-15.png")));
                }
                jLabel37.setText(String.valueOf(parser.getPositives()));
                TotalCount.setText("/" + String.valueOf(parser.getTotal()));
                int m = 0;
                int r;
                int foo = 0;
                int size = parser.getResults().size() / 3;
                int remain = parser.getResults().size() % 3;
                int loop = 0;
                int z = 0;
                for (int j = 0; j < 3; j++) {
                    if (j == 2) {
                        foo = remain;
                    }
                    for (int t = 0; t < size + foo; t++) {
                        r = 0;
                        Antivirus p = parser.getResults().get(loop);
                        JLabel label = new JLabel(p.getName() + " :");
                        label.setBounds(10 + r + z, 0 + m, 120, 20);
                        ResultPanel6.add(label);
                        ResultPanel6.validate();
                        ResultPanel6.repaint();
                        if (!p.isDetected()) {
                            label = new JLabel();
                            label.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/icons8-checkmark-15.png")));
                        } else {
                            label = new JLabel();
                            label.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/icons8-delete-15.png")));
                        }
                        r = 120;
                        label.setBounds(10 + r + z, 0 + m, 50, 20);
                        ResultPanel6.add(label);
                        ResultPanel6.validate();
                        ResultPanel6.repaint();
                        m += 25;
                        loop++;
                    }
                    z += 300;
                    m = 0;
                }
                HomePanel.setVisible(false);
                ScanPanel.setVisible(false);
                ScannedPanel.setVisible(false);
                AboutPanel.setVisible(false);
                ResultPanel.setVisible(true);
                Stable.setVisible(false);
                ResultPanelStable.setVisible(true);
                Cursor cursor2 = new Cursor(Cursor.DEFAULT_CURSOR);
                setCursor(cursor2);
            } else {
                if (save) {
                    this.detectifyDB.insert(url, parser.scanId, "url", null, null, null);
                }
                HomePanel.setVisible(false);
                ScanPanel.setVisible(false);
                Cursor cursor2 = new Cursor(Cursor.DEFAULT_CURSOR);
                setCursor(cursor2);
                ScannedPanel.setVisible(true);
                AboutPanel.setVisible(false);
                ResultPanel.setVisible(false);
                SettingsPanel.setVisible(false);
                jLabel6.setText(ScannedButtonLabel.getText().toUpperCase().replace('İ', 'I'));
                ResultPanelStable.setVisible(false);
                Stable.setVisible(false);
                TotalAll.setText(String.valueOf(this.detectifyDB.getTotalCount()));
                TotalFiles.setText(String.valueOf(this.detectifyDB.getFileCount()));
                TotalURLs.setText(String.valueOf(this.detectifyDB.getURLCount()));
                ScannedFilesStable.setVisible(true);
                this.getScannedFiles();
                pageNumber = 2;
                grafik();
            }
        }

    }

    public void uploadGiven(String fileName, boolean save) throws AWTException {
        File file = new File(fileName);
        files.clear();
        files.add(file);
        MalwareChecker checker = new MalwareChecker();
        String result = checker.post(fileName);
        AntivirusParser parser = new AntivirusParser(result, true);
        if (save) {
            this.detectifyDB.insert(Paths.get(fileName).getFileName().toString(), parser.scanId, "file", Paths.get(fileName).getFileName().toString(), String.valueOf(files.get(0).length()), (files.get(0).getName().substring(files.get(0).getName().lastIndexOf("."), files.get(0).getName().length())));
        }
        HomePanel.setVisible(false);
        ScanPanel.setVisible(false);
        Cursor cursor2 = new Cursor(Cursor.DEFAULT_CURSOR);
        setCursor(cursor2);
        ScannedPanel.setVisible(true);
        AboutPanel.setVisible(false);
        ResultPanel.setVisible(false);
        SettingsPanel.setVisible(false);
        jLabel6.setText(ScannedButtonLabel.getText().toUpperCase().replace('İ', 'I'));
        ResultPanelStable.setVisible(false);
        Stable.setVisible(false);
        TotalAll.setText(String.valueOf(this.detectifyDB.getTotalCount()));
        TotalFiles.setText(String.valueOf(this.detectifyDB.getFileCount()));
        TotalURLs.setText(String.valueOf(this.detectifyDB.getURLCount()));
        ScannedFilesStable.setVisible(true);
        this.getScannedFiles();
        pageNumber = 2;
        grafik();
    }

    public void hashScan(String fileName, String hash) throws NoSuchAlgorithmException, IOException, AWTException {
        HashMap<String, String> params = new HashMap<>();
        params.put("hash", hash);
        MalwareChecker checker = new MalwareChecker();
        String content = checker.get(params, true);
        AntivirusParser parser = new AntivirusParser(content, true);
        if (parser.scanResponse != null) {
            if (parser.isScanSuccess) {
                this.setCurrentReportURL(parser.getPermaLink());
                this.detectifyDB.insert(Paths.get(fileName).getFileName().toString(), parser.scanId, "file", Paths.get(fileName).getFileName().toString(), String.valueOf(files.get(0).length()), (files.get(0).getName().substring(files.get(0).getName().lastIndexOf("."), files.get(0).getName().length())));
                Cursor cursor2 = new Cursor(Cursor.DEFAULT_CURSOR);
                setCursor(cursor2);
                QuestionFrame.setVisible(true);
                SizeLabel.setVisible(true);
                jLabel38.setVisible(true);
                jLabel41.setVisible(true);
                jLabel40.setVisible(true);
                jLabel12.setVisible(true);
                ExtensionLabel.setVisible(true);
                QuestionFrame.setSize(486, 200);
                // NOT: Burası kişiye soru sorulmasına karşın arka planda parse işlemine devam ediyor, bu tamamen işlemleri hızlandırma amacıyla yapıldı statement koymayın.
                if (files.get(0).length() < 1024 * 1024) {
                    FileSize.setText(String.valueOf(files.get(0).length() / (float) 1024).substring(0, 3) + "KB");
                    SizeLabel.setText(FileSize.getText());
                } else {
                    FileSize.setText(String.valueOf(+files.get(0).length() / (float) 1024 / (float) 1024).substring(0, 4) + "MB");
                    SizeLabel.setText(FileSize.getText());
                }
                fileExtension.setText((files.get(0).getName().substring(files.get(0).getName().lastIndexOf("."), files.get(0).getName().length())));
                ExtensionLabel.setText(fileExtension.getText());
                HashLabel.setText(hash.length() > 35 ? hash.substring(0, 35) + "..." : hash);
                FileNameLabel.setText(files.get(0).getName());
                if (parser.getPositives() == 0) {
                    StatusLabel.setForeground(new Color(0, 102, 0));
                    TotalCount.setForeground(new Color(0, 102, 0));
                    Border border = BorderFactory.createLineBorder(new Color(0, 102, 0));
                    jPanel3.setBorder(border);
                    jLabel37.setForeground(new Color(0, 102, 0));
                    jLabel42.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/icons8-checkmark-15.png")));
                    StatusLabel.setText("No malware detected on this file!");
                } else {
                    TotalCount.setForeground(Color.red);
                    Border border = BorderFactory.createLineBorder(Color.red);
                    jPanel3.setBorder(border);
                    jLabel37.setForeground(Color.red);
                    StatusLabel.setForeground(Color.red);
                    StatusLabel.setText(String.format("%d engines detected on this URL", parser.getPositives()));
                    jLabel42.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/icons8-delete-15.png")));
                }
                jLabel37.setText(String.valueOf(parser.getPositives()));
                TotalCount.setText("/" + String.valueOf(parser.getTotal()));
                int m = 0;
                int r;
                int foo = 0;
                int size = parser.getResults().size() / 3;
                int remain = parser.getResults().size() % 3;
                int loop = 0;
                int z = 0;
                for (int j = 0; j < 3; j++) {
                    if (j == 2) {
                        foo = remain;
                    }
                    for (int t = 0; t < size + foo; t++) {
                        r = 0;
                        Antivirus p = parser.getResults().get(loop);
                        JLabel label = new JLabel(p.getName() + " :");
                        label.setBounds(10 + r + z, 0 + m, 120, 20);
                        ResultPanel6.add(label);
                        ResultPanel6.validate();
                        ResultPanel6.repaint();
                        if (!p.isDetected()) {
                            label = new JLabel();
                            label.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/icons8-checkmark-15.png")));
                        } else {
                            label = new JLabel();
                            label.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/icons8-delete-15.png")));
                        }
                        r = 120;
                        label.setBounds(10 + r + z, 0 + m, 50, 20);
                        ResultPanel6.add(label);
                        ResultPanel6.validate();
                        ResultPanel6.repaint();
                        m += 25;
                        loop++;
                    }
                    z += 300;
                    m = 0;

                }

            } else {
                uploadGiven(fileName, true);
            }
        }
    }

    public void scanCheckerFile(String scan_id) throws AWTException {
        HashMap<String, String> params = new HashMap<>();
        params.put("hash", scan_id);
        MalwareChecker checker = new MalwareChecker();
        String content = checker.get(params, true);
        AntivirusParser parser = new AntivirusParser(content, true);
        if (parser.isScanSuccess) {
            this.setCurrentReportURL(parser.getPermaLink());
            SizeLabel.setVisible(true);
            jLabel38.setVisible(true);
            jLabel41.setVisible(true);
            jLabel40.setVisible(true);
            jLabel12.setVisible(true);
            jScrollPane1.setVisible(true);
            QuestionFrame.setVisible(false);

            HomePanel.setVisible(false);
            ScanPanel.setVisible(false);
            ScannedPanel.setVisible(false);
            AboutPanel.setVisible(false);
            ResultPanel.setVisible(true);
            Stable.setVisible(false);
            ResultPanelStable.setVisible(true);
            ExtensionLabel.setVisible(true);
            ArrayList results = this.detectifyDB.select(scan_id);
            HashMap<String, String> result = (HashMap) results.get(0);
            FileNameLabel.setText(result.get("file_name"));
            fileExtension.setText(result.get("file_extension"));
            ExtensionLabel.setText(fileExtension.getText());
            if (Float.parseFloat(result.get("file_size")) < 1024 * 1024) {
                FileSize.setText(String.valueOf(Float.parseFloat(result.get("file_size")) / (float) 1024).substring(0, 3) + "KB");
                SizeLabel.setText(FileSize.getText());
            } else {
                FileSize.setText(String.valueOf(Float.parseFloat(result.get("file_size")) / (float) 1024 / (float) 1024).substring(0, 4) + "MB");
                SizeLabel.setText(FileSize.getText());
            }
            HashLabel.setText(scan_id.length() > 35 ? scan_id.substring(0, 35) + "..." : scan_id);
            if (parser.getPositives() == 0) {
                StatusLabel.setForeground(new Color(0, 102, 0));
                TotalCount.setForeground(new Color(0, 102, 0));
                Border border = BorderFactory.createLineBorder(new Color(0, 102, 0));
                jPanel3.setBorder(border);
                jLabel37.setForeground(new Color(0, 102, 0));
                StatusLabel.setText("No malware detected on this file!");
                jLabel42.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/icons8-checkmark-15.png")));
            } else {
                TotalCount.setForeground(Color.red);
                Border border = BorderFactory.createLineBorder(Color.red);
                jPanel3.setBorder(border);
                jLabel37.setForeground(Color.red);
                StatusLabel.setForeground(Color.red);
                StatusLabel.setText(String.format("%d engines detected on this URL", parser.getPositives()));
                jLabel42.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/icons8-delete-15.png")));
            }
            jLabel37.setText(String.valueOf(parser.getPositives()));
            TotalCount.setText("/" + String.valueOf(parser.getTotal()));
            int m = 0;
            int r;
            int foo = 0;
            int size = parser.getResults().size() / 3;
            int remain = parser.getResults().size() % 3;
            int loop = 0;
            int z = 0;
            for (int j = 0; j < 3; j++) {
                if (j == 2) {
                    foo = remain;
                }
                for (int t = 0; t < size + foo; t++) {
                    r = 0;
                    Antivirus p = parser.getResults().get(loop);
                    JLabel label = new JLabel(p.getName() + " :");
                    label.setBounds(10 + r + z, 0 + m, 120, 20);
                    ResultPanel6.add(label);
                    ResultPanel6.validate();
                    ResultPanel6.repaint();
                    if (!p.isDetected()) {
                        label = new JLabel();
                        label.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/icons8-checkmark-15.png")));
                    } else {
                        label = new JLabel();
                        label.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/icons8-delete-15.png")));
                    }
                    r = 120;
                    label.setBounds(10 + r + z, 0 + m, 50, 20);
                    ResultPanel6.add(label);
                    ResultPanel6.validate();
                    ResultPanel6.repaint();

                    m += 25;
                    loop++;
                }
                z += 300;
                m = 0;
            }
        }
    }

    public void grafik() {
        // Home
        switch (pageNumber) {
            case 0:
                ResultPanelStable.setVisible(false);
                HomeButtonPanel.setBackground(new Color(85, 65, 118));
                ScanButtonPanel.setBackground(new Color(64, 43, 100));
                ScannedButtonPanel.setBackground(new Color(64, 43, 100));
                AboutButtonPanel.setBackground(new Color(64, 43, 100));
                SettingsButtonPanel.setBackground(new Color(64, 43, 100));
                break;
            case 1:
                // Scan
                ScanButtonPanel.setBackground(new Color(85, 65, 118));
                HomeButtonPanel.setBackground(new Color(64, 43, 100));
                ScannedButtonPanel.setBackground(new Color(64, 43, 100));
                AboutButtonPanel.setBackground(new Color(64, 43, 100));
                SettingsButtonPanel.setBackground(new Color(64, 43, 100));
                break;
            case 2:
                // Scanned Files
                ScannedButtonPanel.setBackground(new Color(85, 65, 118));
                ScanButtonPanel.setBackground(new Color(64, 43, 100));
                HomeButtonPanel.setBackground(new Color(64, 43, 100));
                AboutButtonPanel.setBackground(new Color(64, 43, 100));
                SettingsButtonPanel.setBackground(new Color(64, 43, 100));
                break;
            case 3:
                // About Us
                AboutButtonPanel.setBackground(new Color(85, 65, 118));
                ScanButtonPanel.setBackground(new Color(64, 43, 100));
                ScannedButtonPanel.setBackground(new Color(64, 43, 100));
                HomeButtonPanel.setBackground(new Color(64, 43, 100));
                SettingsButtonPanel.setBackground(new Color(64, 43, 100));
                break;
            case 4:
                // Settings
                this.getAPIKey();
                SettingsButtonPanel.setBackground(new Color(85, 65, 118));
                AboutButtonPanel.setBackground(new Color(64, 43, 100));
                ScanButtonPanel.setBackground(new Color(64, 43, 100));
                ScannedButtonPanel.setBackground(new Color(64, 43, 100));
                HomeButtonPanel.setBackground(new Color(64, 43, 100));
                break;
            default:
                SettingsButtonPanel.setBackground(new Color(64, 43, 100));
                HomeButtonPanel.setBackground(new Color(64, 43, 100));
                ScanButtonPanel.setBackground(new Color(64, 43, 100));
                ScannedButtonPanel.setBackground(new Color(64, 43, 100));
                AboutButtonPanel.setBackground(new Color(64, 43, 100));
                break;
        }
    }

    public void changeTurkish() {
        Text.setText("Şüpheli gördüğünüz dosyaları");
        Text2.setText("   analiz etmenizi sağlar");
        HomeButtonLabel.setText("Ana Menü");
        ScanButtonLabel.setText("Tara");
        ScannedButtonLabel.setText("Taranmış Dosyalar");
        AboutButtonLabel.setText("Hakkımızda");
        jLabel13.setText("Detectify Nedir?");
        jLabel14.setText("Nasıl Çalışır?");
        jLabel3.setText("İşletim Sistemi:");
        jLabel9.setText("İşletim Sistemi Türü:");
        jLabel18.setText("Sistem versiyonu:");
        jLabel6.setText("ANA MENU");
        jLabel33.setText("Sistem Bilgisi");
        jLabel25.setText("DOSYA");
        Scan.setText("TARA");
        NameLabel.setText("Dosya Adı:");
        PathLabel.setText("Dosya Yolu:");
        jLabel27.setText("         Sürükle Bırak");
        jLabel28.setText("veya");
        FExtensionLabel.setText("Dosya Türü:");
        FSizeLabel.setText("Dosya Boyutu:");
        jLabel6.setText("AYARLAR");
        jLabel7.setText("    Detectify, şüpheli gördüğünüz dosyaları, hashleri ve URL'leri taramanıza");
        jLabel12.setText(" imkan sağlayan VirusTotal alt yapısını kullanan ücretsiz bir programdır.");
        jLabel15.setText("    Detectify, VirusTotal Public API'ını kullanarak dosya yüklemesi, URL ve hash");
        jLabel16.setText("  taraması gibi özellikleri tamamen ücretsiz bir şekilde kullanmanızı sağlar.");
        jLabel2.setText("API Anahtarını Değiştir:");
        jLabel11.setText("Uyarı! Bu Anahtar tarama işlemlerinde kullanılacaktır.");
        fileName.setText("Dosya Seçilmedi!");
        jLabel17.setText("");
        Status.setText("En fazla 32 MB boyuta sahip bir dosya taratabilirsiniz!");
        jButton1.setText("Dosya seç");
        SettingsButtonLabel.setText("Ayarlar");
        jLabel39.setText("Taranmış Dosya ve URL");
        jLabel49.setText("Taranmış Dosyalar");
        jLabel52.setText("Taranmış URL'ler");
        con = 0;
    }

    public void changeEnglish() {
        Text.setText("Analyze suspicious files and URLs   ");
        Text2.setText("to detect types of malwares. ");
        HomeButtonLabel.setText("Home");
        ScanButtonLabel.setText("Scan");
        ScannedButtonLabel.setText("Scanned Files");
        AboutButtonLabel.setText("About Us");
        jLabel13.setText("What is Detectify?");
        jLabel14.setText("How it Works?");
        jLabel3.setText("Operating System:");
        jLabel9.setText("Operating System Type:");
        jLabel18.setText("Operating System Version:");
        jLabel6.setText("HOME");
        jLabel25.setText("FILE");
        Scan.setText("SCAN");
        jLabel33.setText("System Information");
        NameLabel.setText("File Name:");
        jLabel27.setText("Drag and Drop file here");
        jLabel28.setText("or");
        FExtensionLabel.setText("File Extension:");
        PathLabel.setText("File Path:");
        FSizeLabel.setText("File Size:");
        jLabel7.setText("    Detectify is a free virus, malware and URL online scanning service.");
        jLabel15.setText("    Detectify is using Public API of VirusTotal. The API lets us upload and scan files,");
        jLabel16.setText(" URLs, access finished scan reports and make automatic comments without the");
        jLabel2.setText("Change API Keys:");
        jLabel17.setText(" need of using the website interface..");
        jLabel11.setText("Warning this key is using during your file scanning operations.");
        fileName.setText("There is no file selected!");
        con = 1;
        Status.setText("You can scan a file with size at most 32MB!");
        jButton1.setText("Choose file");
        jLabel12.setVisible(false);
        SettingsButtonLabel.setText("Settings");
        jLabel39.setText("Total Scanned files and URLs");
        jLabel49.setText("Total Scanned files");
        jLabel52.setText("Total Scanned URLs");

    }

    /**
     * Creates new form GUI
     */
    public static int Flag = 0;
    public static int pageNumber = 0;
    public static int count = 1;
    static int counter5 = 0;
    public DatabaseOperations detectifyDB;
    public boolean a = true;
    ArrayList<File> files = new ArrayList<>();
    String fileName2;

    public GUI() {
        Path currentRelativePath = Paths.get("");
        String s = currentRelativePath.toAbsolutePath().toString();
        File directory = new File(s + "/db");
        if (!directory.exists()) {
            directory.mkdir();
        }
        initComponents();
        this.setLocationRelativeTo(null);
        modifyLabel();
        this.grafik();
        // Database ops.
        this.detectifyDB = new DatabaseOperations();
        this.detectifyDB.connect();
        this.detectifyDB.initAPIKeyTable();
        this.detectifyDB.initResultTable();
        ImageIcon img = new ImageIcon("src\\Images\\icons8-spyware-64.png");
        this.setIconImage(img.getImage());
    }

    public void modifyLabel() {
        TransferHandler th = null;
        th = new TransferHandler() {
            @Override
            public boolean canImport(JComponent comp, DataFlavor[] trasferFlavors) {
                return true;
            }

            @Override
            public boolean importData(JComponent comp, Transferable t) {
                try {
                    files.clear();
                    List<File> s = (List<File>) t.getTransferData(DataFlavor.javaFileListFlavor);
                    File file = s.get(0);
                    files.add(s.get(0));
                    FileName.setVisible(true);
                    jLabel32.setText(file.getName().length() > 15 ? file.getName().substring(0, 15) + "..." : file.getName());
                    fileName.setText(file.getName().length() > 35 ? file.getName().substring(0, 35) + "..." : file.getName());
                    FileNameLabel.setText(fileName.getText());
                    fileName2 = file.getPath();
                    filePath.setText(file.getPath().length() > 42 ? file.getPath().substring(0, 42) + "..." : file.getPath());
                    if (file.length() < 1024 * 1024) {
                        FileSize.setText(String.valueOf((float) file.length() / (float) 1024).substring(0, 3) + "KB");
                        SizeLabel.setText(FileSize.getText());
                    } else {
                        FileSize.setText(String.valueOf((float) file.length() / (float) 1024 / (float) 1024).substring(0, 4) + "MB");
                        SizeLabel.setText(FileSize.getText());
                    }
                    fileExtension.setText((file.getName().substring(file.getName().lastIndexOf("."), file.getName().length())));
                    ExtensionLabel.setText(fileExtension.getText());
                    if (file.length() > 33554432) {
                        sizeController = 1;
                        StatusIcon.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/icons8-error-15.png")));
                        StatusIcon.setVisible(true);
                    } else {
                        sizeController = 0;
                        StatusIcon.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/icons8-checkmark-15.png")));
                        StatusIcon.setVisible(true);
                    }

                } catch (UnsupportedFlavorException ex) {
                    Logger.getLogger(GUI.class
                            .getName()).log(Level.SEVERE, null, ex);
                } catch (IOException ex) {
                    Logger.getLogger(GUI.class
                            .getName()).log(Level.SEVERE, null, ex);
                }
                return true;
            }
        };
        DragAndDrop.setTransferHandler(th);
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        QuestionFrame = new javax.swing.JFrame();
        jPanel11 = new javax.swing.JPanel();
        jLabel44 = new javax.swing.JLabel();
        ScanAgain = new javax.swing.JButton();
        SeeResult = new javax.swing.JButton();
        GeneralPanel = new javax.swing.JPanel();
        MenuPanel = new javax.swing.JPanel();
        HomeButtonPanel = new javax.swing.JPanel();
        HomeButtonLabel = new javax.swing.JLabel();
        ScanButtonPanel = new javax.swing.JPanel();
        ScanButtonLabel = new javax.swing.JLabel();
        ScannedButtonPanel = new javax.swing.JPanel();
        ScannedButtonLabel = new javax.swing.JLabel();
        AboutButtonPanel = new javax.swing.JPanel();
        AboutButtonLabel = new javax.swing.JLabel();
        Logo = new javax.swing.JLabel();
        Language = new javax.swing.JPanel();
        SelectedFlag = new javax.swing.JLabel();
        jLabel5 = new javax.swing.JLabel();
        Languages = new javax.swing.JPanel();
        FirstFlag = new javax.swing.JPanel();
        jLabel4 = new javax.swing.JLabel();
        Text = new javax.swing.JLabel();
        Text2 = new javax.swing.JLabel();
        SettingsButtonPanel = new javax.swing.JPanel();
        SettingsButtonLabel = new javax.swing.JLabel();
        jLabel35 = new javax.swing.JLabel();
        ContentPanel = new javax.swing.JPanel();
        MainPanel = new javax.swing.JPanel();
        CustomTitleBar = new javax.swing.JPanel();
        ClosePanel = new javax.swing.JPanel();
        CloseLabel = new javax.swing.JLabel();
        MinimisePanel = new javax.swing.JPanel();
        minimise = new javax.swing.JLabel();
        Pannels = new javax.swing.JPanel();
        HomePanel = new javax.swing.JPanel();
        SystemInformation = new javax.swing.JPanel();
        jLabel3 = new javax.swing.JLabel();
        OS = new javax.swing.JLabel();
        jLabel9 = new javax.swing.JLabel();
        jLabel10 = new javax.swing.JLabel();
        jLabel18 = new javax.swing.JLabel();
        jLabel19 = new javax.swing.JLabel();
        jLabel33 = new javax.swing.JLabel();
        jLabel7 = new javax.swing.JLabel();
        jLabel14 = new javax.swing.JLabel();
        jLabel15 = new javax.swing.JLabel();
        jLabel16 = new javax.swing.JLabel();
        jLabel17 = new javax.swing.JLabel();
        jLabel21 = new javax.swing.JLabel();
        jLabel13 = new javax.swing.JLabel();
        jLabel12 = new javax.swing.JLabel();
        ScanPanel = new javax.swing.JPanel();
        ScanChooseBoxes = new javax.swing.JPanel();
        URL = new javax.swing.JPanel();
        jLabel26 = new javax.swing.JLabel();
        jLabel31 = new javax.swing.JLabel();
        FILE = new javax.swing.JPanel();
        jLabel25 = new javax.swing.JLabel();
        jLabel29 = new javax.swing.JLabel();
        ScanContent = new javax.swing.JPanel();
        FilePanel = new javax.swing.JPanel();
        jPanel12 = new javax.swing.JPanel();
        DragAndDrop = new javax.swing.JLabel();
        jLabel27 = new javax.swing.JLabel();
        jLabel28 = new javax.swing.JLabel();
        jButton1 = new javax.swing.JButton();
        FileName = new javax.swing.JPanel();
        jLabel34 = new javax.swing.JLabel();
        jLabel32 = new javax.swing.JLabel();
        jPanel13 = new javax.swing.JPanel();
        NameLabel = new javax.swing.JLabel();
        fileName = new javax.swing.JLabel();
        PathLabel = new javax.swing.JLabel();
        filePath = new javax.swing.JLabel();
        FSizeLabel = new javax.swing.JLabel();
        FileSize = new javax.swing.JLabel();
        FExtensionLabel = new javax.swing.JLabel();
        fileExtension = new javax.swing.JLabel();
        StatusPanel = new javax.swing.JPanel();
        Status = new javax.swing.JLabel();
        StatusIcon = new javax.swing.JLabel();
        ScanButton = new javax.swing.JPanel();
        Scan = new javax.swing.JLabel();
        URLPanel = new javax.swing.JPanel();
        URLTf = new javax.swing.JTextField();
        SearchButton = new javax.swing.JLabel();
        WWWLogo = new javax.swing.JLabel();
        ScannedPanel = new javax.swing.JPanel();
        jLabel1 = new javax.swing.JLabel();
        DatabaseData = new javax.swing.JScrollPane();
        jTable1 = new javax.swing.JTable();
        SettingsPanel = new javax.swing.JPanel();
        SettingContent = new javax.swing.JPanel();
        jLabel2 = new javax.swing.JLabel();
        apiKeyText = new javax.swing.JTextField();
        jLabel11 = new javax.swing.JLabel();
        SaveButton = new javax.swing.JButton();
        ApiKeyStatus = new javax.swing.JLabel();
        ResultPanel = new javax.swing.JPanel();
        jScrollPane1 = new javax.swing.JScrollPane();
        ResultPanel6 = new javax.swing.JPanel();
        AboutPanel = new javax.swing.JPanel();
        jLabel30 = new javax.swing.JLabel();
        jLabel22 = new javax.swing.JLabel();
        jLabel24 = new javax.swing.JLabel();
        jLabel43 = new javax.swing.JLabel();
        jLabel46 = new javax.swing.JLabel();
        jLabel48 = new javax.swing.JLabel();
        StableBig = new javax.swing.JPanel();
        Stable = new javax.swing.JPanel();
        jLabel6 = new javax.swing.JLabel();
        jLabel8 = new javax.swing.JLabel();
        ResultPanelStable = new javax.swing.JPanel();
        FileNameLabel = new javax.swing.JLabel();
        ExtensionLabel = new javax.swing.JLabel();
        jPanel3 = new javax.swing.JPanel();
        jLabel37 = new javax.swing.JLabel();
        TotalCount = new javax.swing.JLabel();
        HashLabel = new javax.swing.JLabel();
        SizeLabel = new javax.swing.JLabel();
        jLabel38 = new javax.swing.JLabel();
        jLabel40 = new javax.swing.JLabel();
        jLabel41 = new javax.swing.JLabel();
        jPanel15 = new javax.swing.JPanel();
        StatusLabel = new javax.swing.JLabel();
        jLabel42 = new javax.swing.JLabel();
        jLabel36 = new javax.swing.JLabel();
        FileTypeLabel = new javax.swing.JLabel();
        ScannedFilesStable = new javax.swing.JPanel();
        ScannedFilesInfoBoxes = new javax.swing.JPanel();
        AllTotal = new javax.swing.JPanel();
        jLabel39 = new javax.swing.JLabel();
        jPanel18 = new javax.swing.JPanel();
        jLabel45 = new javax.swing.JLabel();
        TotalAll = new javax.swing.JLabel();
        FilesTotal = new javax.swing.JPanel();
        jLabel49 = new javax.swing.JLabel();
        jPanel22 = new javax.swing.JPanel();
        jLabel50 = new javax.swing.JLabel();
        TotalFiles = new javax.swing.JLabel();
        URLTotal = new javax.swing.JPanel();
        jLabel52 = new javax.swing.JLabel();
        jPanel24 = new javax.swing.JPanel();
        jLabel53 = new javax.swing.JLabel();
        TotalURLs = new javax.swing.JLabel();

        QuestionFrame.setBackground(new java.awt.Color(255, 255, 255));
        QuestionFrame.setLocationRelativeTo(null);
        QuestionFrame.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mousePressed(java.awt.event.MouseEvent evt) {
                QuestionFrameMousePressed(evt);
            }
        });

        jPanel11.setBackground(new java.awt.Color(250, 250, 250));

        jLabel44.setFont(new java.awt.Font("Segoe UI", 0, 14)); // NOI18N
        jLabel44.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel44.setText("File has found in VirusTotal's database, do you want scan again?");

        ScanAgain.setText("Yes");
        ScanAgain.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                ScanAgainActionPerformed(evt);
            }
        });

        SeeResult.setText("No, show the results");
        SeeResult.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                SeeResultActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel11Layout = new javax.swing.GroupLayout(jPanel11);
        jPanel11.setLayout(jPanel11Layout);
        jPanel11Layout.setHorizontalGroup(
            jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel11Layout.createSequentialGroup()
                .addGap(47, 47, 47)
                .addComponent(jLabel44)
                .addContainerGap(48, Short.MAX_VALUE))
            .addGroup(jPanel11Layout.createSequentialGroup()
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(ScanAgain)
                .addGap(75, 75, 75)
                .addComponent(SeeResult)
                .addGap(85, 85, 85))
        );
        jPanel11Layout.setVerticalGroup(
            jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel11Layout.createSequentialGroup()
                .addGap(40, 40, 40)
                .addComponent(jLabel44)
                .addGap(30, 30, 30)
                .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(ScanAgain)
                    .addComponent(SeeResult))
                .addContainerGap(45, Short.MAX_VALUE))
        );

        javax.swing.GroupLayout QuestionFrameLayout = new javax.swing.GroupLayout(QuestionFrame.getContentPane());
        QuestionFrame.getContentPane().setLayout(QuestionFrameLayout);
        QuestionFrameLayout.setHorizontalGroup(
            QuestionFrameLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jPanel11, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        );
        QuestionFrameLayout.setVerticalGroup(
            QuestionFrameLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jPanel11, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        );

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle("Detectify");
        setBackground(new java.awt.Color(102, 102, 102));
        setCursor(new java.awt.Cursor(java.awt.Cursor.DEFAULT_CURSOR));
        setForeground(new java.awt.Color(102, 102, 102));
        setUndecorated(true);

        GeneralPanel.setBackground(new java.awt.Color(255, 255, 255));
        GeneralPanel.setLayout(null);

        MenuPanel.setBackground(new java.awt.Color(54, 33, 89));
        MenuPanel.setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

        HomeButtonPanel.setBackground(new java.awt.Color(64, 43, 100));

        HomeButtonLabel.setFont(new java.awt.Font("Segoe UI", 0, 14)); // NOI18N
        HomeButtonLabel.setForeground(new java.awt.Color(255, 255, 255));
        HomeButtonLabel.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/Ev.png"))); // NOI18N
        HomeButtonLabel.setText("Home");
        HomeButtonLabel.addMouseMotionListener(new java.awt.event.MouseMotionAdapter() {
            public void mouseDragged(java.awt.event.MouseEvent evt) {
                HomeButtonLabelMouseDragged(evt);
            }
        });
        HomeButtonLabel.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                HomeClicked(evt);
            }
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                HomeEntered(evt);
            }
            public void mouseExited(java.awt.event.MouseEvent evt) {
                HomeButtonLabelMouseExited(evt);
            }
            public void mousePressed(java.awt.event.MouseEvent evt) {
                HomeButtonLabelMousePressed(evt);
            }
        });

        javax.swing.GroupLayout HomeButtonPanelLayout = new javax.swing.GroupLayout(HomeButtonPanel);
        HomeButtonPanel.setLayout(HomeButtonPanelLayout);
        HomeButtonPanelLayout.setHorizontalGroup(
            HomeButtonPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(HomeButtonPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(HomeButtonLabel, javax.swing.GroupLayout.DEFAULT_SIZE, 190, Short.MAX_VALUE)
                .addContainerGap())
        );
        HomeButtonPanelLayout.setVerticalGroup(
            HomeButtonPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(HomeButtonLabel, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 50, Short.MAX_VALUE)
        );

        MenuPanel.add(HomeButtonPanel, new org.netbeans.lib.awtextra.AbsoluteConstraints(0, 130, 210, 50));

        ScanButtonPanel.setBackground(new java.awt.Color(64, 43, 100));

        ScanButtonLabel.setFont(new java.awt.Font("Segoe UI", 0, 14)); // NOI18N
        ScanButtonLabel.setForeground(new java.awt.Color(255, 255, 255));
        ScanButtonLabel.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/finger.png"))); // NOI18N
        ScanButtonLabel.setText("Scan");
        ScanButtonLabel.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                ScanButtonLabelMouseClicked(evt);
            }
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                ScanButtonLabelMouseEntered(evt);
            }
            public void mouseExited(java.awt.event.MouseEvent evt) {
                ScanButtonLabelMouseExited(evt);
            }
            public void mousePressed(java.awt.event.MouseEvent evt) {
                ScanBuutonMousePressed(evt);
            }
        });

        javax.swing.GroupLayout ScanButtonPanelLayout = new javax.swing.GroupLayout(ScanButtonPanel);
        ScanButtonPanel.setLayout(ScanButtonPanelLayout);
        ScanButtonPanelLayout.setHorizontalGroup(
            ScanButtonPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(ScanButtonPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(ScanButtonLabel, javax.swing.GroupLayout.DEFAULT_SIZE, 200, Short.MAX_VALUE))
        );
        ScanButtonPanelLayout.setVerticalGroup(
            ScanButtonPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(ScanButtonLabel, javax.swing.GroupLayout.DEFAULT_SIZE, 50, Short.MAX_VALUE)
        );

        MenuPanel.add(ScanButtonPanel, new org.netbeans.lib.awtextra.AbsoluteConstraints(0, 180, 210, 50));

        ScannedButtonPanel.setBackground(new java.awt.Color(64, 43, 100));

        ScannedButtonLabel.setFont(new java.awt.Font("Segoe UI", 0, 14)); // NOI18N
        ScannedButtonLabel.setForeground(new java.awt.Color(255, 255, 255));
        ScannedButtonLabel.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/icons8-file-15.png"))); // NOI18N
        ScannedButtonLabel.setText("Scanned Files");
        ScannedButtonLabel.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                ScannedButtonLabelMouseClicked(evt);
            }
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                ScannedButtonLabelMouseEntered(evt);
            }
            public void mouseExited(java.awt.event.MouseEvent evt) {
                ScannedButtonLabelMouseExited(evt);
            }
            public void mousePressed(java.awt.event.MouseEvent evt) {
                ScannedButtonLabelMousePressed(evt);
            }
        });

        javax.swing.GroupLayout ScannedButtonPanelLayout = new javax.swing.GroupLayout(ScannedButtonPanel);
        ScannedButtonPanel.setLayout(ScannedButtonPanelLayout);
        ScannedButtonPanelLayout.setHorizontalGroup(
            ScannedButtonPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, ScannedButtonPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(ScannedButtonLabel, javax.swing.GroupLayout.DEFAULT_SIZE, 200, Short.MAX_VALUE))
        );
        ScannedButtonPanelLayout.setVerticalGroup(
            ScannedButtonPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(ScannedButtonLabel, javax.swing.GroupLayout.DEFAULT_SIZE, 50, Short.MAX_VALUE)
        );

        MenuPanel.add(ScannedButtonPanel, new org.netbeans.lib.awtextra.AbsoluteConstraints(0, 230, 210, 50));

        AboutButtonPanel.setBackground(new java.awt.Color(64, 43, 100));

        AboutButtonLabel.setFont(new java.awt.Font("Segoe UI", 0, 14)); // NOI18N
        AboutButtonLabel.setForeground(new java.awt.Color(255, 255, 255));
        AboutButtonLabel.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/question.png"))); // NOI18N
        AboutButtonLabel.setText("About Us");
        AboutButtonLabel.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                AboutButtonLabelMouseClicked(evt);
            }
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                AboutButtonLabelMouseEntered(evt);
            }
            public void mouseExited(java.awt.event.MouseEvent evt) {
                AboutButtonLabelMouseExited(evt);
            }
            public void mousePressed(java.awt.event.MouseEvent evt) {
                AboutButtonLabelMousePressed(evt);
            }
        });

        javax.swing.GroupLayout AboutButtonPanelLayout = new javax.swing.GroupLayout(AboutButtonPanel);
        AboutButtonPanel.setLayout(AboutButtonPanelLayout);
        AboutButtonPanelLayout.setHorizontalGroup(
            AboutButtonPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(AboutButtonPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(AboutButtonLabel, javax.swing.GroupLayout.DEFAULT_SIZE, 200, Short.MAX_VALUE))
        );
        AboutButtonPanelLayout.setVerticalGroup(
            AboutButtonPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(AboutButtonLabel, javax.swing.GroupLayout.DEFAULT_SIZE, 50, Short.MAX_VALUE)
        );

        MenuPanel.add(AboutButtonPanel, new org.netbeans.lib.awtextra.AbsoluteConstraints(0, 280, 210, 50));

        Logo.setFont(new java.awt.Font("Tahoma", 0, 26)); // NOI18N
        Logo.setForeground(new java.awt.Color(255, 255, 255));
        Logo.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        Logo.setText("Detectify");
        MenuPanel.add(Logo, new org.netbeans.lib.awtextra.AbsoluteConstraints(0, 20, 210, 40));

        Language.setBackground(new java.awt.Color(54, 33, 89));

        SelectedFlag.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        SelectedFlag.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/USA Flag.png"))); // NOI18N
        SelectedFlag.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                SelectedFlagMouseEntered(evt);
            }
            public void mouseExited(java.awt.event.MouseEvent evt) {
                SelectedFlagMouseExited(evt);
            }
        });

        jLabel5.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/icons8-collapse-arrow-24.png"))); // NOI18N
        jLabel5.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                jLabel5MouseEntered(evt);
            }
            public void mouseExited(java.awt.event.MouseEvent evt) {
                jLabel5MouseExited(evt);
            }
            public void mousePressed(java.awt.event.MouseEvent evt) {
                jLabel5MousePressed(evt);
            }
        });

        javax.swing.GroupLayout LanguageLayout = new javax.swing.GroupLayout(Language);
        Language.setLayout(LanguageLayout);
        LanguageLayout.setHorizontalGroup(
            LanguageLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(LanguageLayout.createSequentialGroup()
                .addComponent(SelectedFlag)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jLabel5)
                .addGap(0, 0, Short.MAX_VALUE))
        );
        LanguageLayout.setVerticalGroup(
            LanguageLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(SelectedFlag, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, LanguageLayout.createSequentialGroup()
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(jLabel5)
                .addContainerGap())
        );

        MenuPanel.add(Language, new org.netbeans.lib.awtextra.AbsoluteConstraints(10, 440, -1, 40));

        Languages.setBackground(new java.awt.Color(54, 33, 89));
        Languages.setVisible(false);

        FirstFlag.setBackground(new java.awt.Color(54, 33, 89));

        jLabel4.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/Turkish.png"))); // NOI18N
        jLabel4.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                jLabel4MouseEntered(evt);
            }
            public void mouseExited(java.awt.event.MouseEvent evt) {
                jLabel4MouseExited(evt);
            }
            public void mousePressed(java.awt.event.MouseEvent evt) {
                jLabel4MousePressed(evt);
            }
        });

        javax.swing.GroupLayout FirstFlagLayout = new javax.swing.GroupLayout(FirstFlag);
        FirstFlag.setLayout(FirstFlagLayout);
        FirstFlagLayout.setHorizontalGroup(
            FirstFlagLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(FirstFlagLayout.createSequentialGroup()
                .addComponent(jLabel4)
                .addGap(0, 38, Short.MAX_VALUE))
        );
        FirstFlagLayout.setVerticalGroup(
            FirstFlagLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jLabel4)
        );

        javax.swing.GroupLayout LanguagesLayout = new javax.swing.GroupLayout(Languages);
        Languages.setLayout(LanguagesLayout);
        LanguagesLayout.setHorizontalGroup(
            LanguagesLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(FirstFlag, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        );
        LanguagesLayout.setVerticalGroup(
            LanguagesLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, LanguagesLayout.createSequentialGroup()
                .addGap(0, 8, Short.MAX_VALUE)
                .addComponent(FirstFlag, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
        );

        MenuPanel.add(Languages, new org.netbeans.lib.awtextra.AbsoluteConstraints(10, 400, 70, 40));

        Text.setFont(new java.awt.Font("Segoe UI", 0, 11)); // NOI18N
        Text.setForeground(new java.awt.Color(255, 255, 255));
        Text.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        Text.setText("Analyze suspicious files and URLs   ");
        MenuPanel.add(Text, new org.netbeans.lib.awtextra.AbsoluteConstraints(20, 70, -1, -1));

        Text2.setFont(new java.awt.Font("Segoe UI", 0, 11)); // NOI18N
        Text2.setForeground(new java.awt.Color(255, 255, 255));
        Text2.setText("to detect types of malwares. ");
        MenuPanel.add(Text2, new org.netbeans.lib.awtextra.AbsoluteConstraints(30, 90, -1, -1));

        SettingsButtonPanel.setBackground(new java.awt.Color(64, 43, 100));

        SettingsButtonLabel.setBackground(new java.awt.Color(255, 255, 255));
        SettingsButtonLabel.setFont(new java.awt.Font("Segoe UI", 0, 14)); // NOI18N
        SettingsButtonLabel.setForeground(new java.awt.Color(255, 255, 255));
        SettingsButtonLabel.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/Settings.png"))); // NOI18N
        SettingsButtonLabel.setText("Settings");
        SettingsButtonLabel.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                SettingsButtonLabelMouseClicked(evt);
            }
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                SettingsButtonLabelMouseEntered(evt);
            }
            public void mouseExited(java.awt.event.MouseEvent evt) {
                SettingsButtonLabelMouseExited(evt);
            }
            public void mousePressed(java.awt.event.MouseEvent evt) {
                SettingsButtonLabelMousePressed(evt);
            }
        });

        javax.swing.GroupLayout SettingsButtonPanelLayout = new javax.swing.GroupLayout(SettingsButtonPanel);
        SettingsButtonPanel.setLayout(SettingsButtonPanelLayout);
        SettingsButtonPanelLayout.setHorizontalGroup(
            SettingsButtonPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, SettingsButtonPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(SettingsButtonLabel, javax.swing.GroupLayout.DEFAULT_SIZE, 200, Short.MAX_VALUE))
        );
        SettingsButtonPanelLayout.setVerticalGroup(
            SettingsButtonPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(SettingsButtonLabel, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 50, Short.MAX_VALUE)
        );

        MenuPanel.add(SettingsButtonPanel, new org.netbeans.lib.awtextra.AbsoluteConstraints(0, 330, 210, 50));

        jLabel35.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/icons8-github-25.png"))); // NOI18N
        jLabel35.setToolTipText("See open-source code");
        jLabel35.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                jLabel35MouseEntered(evt);
            }
            public void mouseExited(java.awt.event.MouseEvent evt) {
                jLabel35MouseExited(evt);
            }
            public void mousePressed(java.awt.event.MouseEvent evt) {
                jLabel35MousePressed(evt);
            }
        });
        MenuPanel.add(jLabel35, new org.netbeans.lib.awtextra.AbsoluteConstraints(170, 450, -1, -1));

        GeneralPanel.add(MenuPanel);
        MenuPanel.setBounds(0, 0, 210, 490);

        ContentPanel.setBackground(new java.awt.Color(102, 102, 102));
        ContentPanel.setLayout(new java.awt.CardLayout());

        MainPanel.setBackground(new java.awt.Color(255, 255, 255));

        CustomTitleBar.setBackground(new java.awt.Color(255, 255, 255));
        CustomTitleBar.addMouseMotionListener(new java.awt.event.MouseMotionAdapter() {
            public void mouseDragged(java.awt.event.MouseEvent evt) {
                CustomTitleBarMouseDragged(evt);
            }
        });
        CustomTitleBar.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mousePressed(java.awt.event.MouseEvent evt) {
                CustomTitleBarMousePressed(evt);
            }
        });
        CustomTitleBar.setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

        ClosePanel.setBackground(new java.awt.Color(255, 255, 255));
        ClosePanel.setPreferredSize(new java.awt.Dimension(76, 28));

        CloseLabel.setBackground(new java.awt.Color(54, 33, 89));
        CloseLabel.setFont(new java.awt.Font("Segoe UI", 1, 18)); // NOI18N
        CloseLabel.setForeground(new java.awt.Color(54, 33, 89));
        CloseLabel.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        CloseLabel.setText("X");
        CloseLabel.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                CloseLabelMouseClicked(evt);
            }
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                CloseLabelMouseEntered(evt);
            }
            public void mouseExited(java.awt.event.MouseEvent evt) {
                CloseLabelMouseExited(evt);
            }
            public void mousePressed(java.awt.event.MouseEvent evt) {
                CloseLabelMousePressed(evt);
            }
        });

        javax.swing.GroupLayout ClosePanelLayout = new javax.swing.GroupLayout(ClosePanel);
        ClosePanel.setLayout(ClosePanelLayout);
        ClosePanelLayout.setHorizontalGroup(
            ClosePanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(CloseLabel, javax.swing.GroupLayout.DEFAULT_SIZE, 60, Short.MAX_VALUE)
        );
        ClosePanelLayout.setVerticalGroup(
            ClosePanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, ClosePanelLayout.createSequentialGroup()
                .addGap(0, 0, Short.MAX_VALUE)
                .addComponent(CloseLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 28, javax.swing.GroupLayout.PREFERRED_SIZE))
        );

        CustomTitleBar.add(ClosePanel, new org.netbeans.lib.awtextra.AbsoluteConstraints(720, 0, 60, -1));

        MinimisePanel.setBackground(new java.awt.Color(255, 255, 255));
        MinimisePanel.setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

        minimise.setFont(new java.awt.Font("Tahoma", 1, 18)); // NOI18N
        minimise.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        minimise.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/- ikonu.png"))); // NOI18N
        minimise.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                minimiseMouseClicked(evt);
            }
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                minimiseMouseEntered(evt);
            }
            public void mouseExited(java.awt.event.MouseEvent evt) {
                minimiseMouseExited(evt);
            }
        });
        MinimisePanel.add(minimise, new org.netbeans.lib.awtextra.AbsoluteConstraints(0, 0, 60, 30));

        CustomTitleBar.add(MinimisePanel, new org.netbeans.lib.awtextra.AbsoluteConstraints(660, 0, 60, 30));

        Pannels.setLayout(new java.awt.CardLayout());

        HomePanel.setBackground(new java.awt.Color(255, 255, 255));

        SystemInformation.setBackground(new java.awt.Color(64, 43, 100));
        SystemInformation.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(255, 255, 255), 2));
        SystemInformation.setForeground(new java.awt.Color(255, 255, 255));
        SystemInformation.setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

        jLabel3.setFont(new java.awt.Font("Tahoma", 1, 11)); // NOI18N
        jLabel3.setForeground(new java.awt.Color(255, 255, 255));
        jLabel3.setText("Operating System :");
        SystemInformation.add(jLabel3, new org.netbeans.lib.awtextra.AbsoluteConstraints(10, 60, -1, -1));

        String osName = System.getProperty("os.name");
        OS.setText(osName);
        OS.setForeground(new java.awt.Color(255, 255, 255));
        SystemInformation.add(OS, new org.netbeans.lib.awtextra.AbsoluteConstraints(130, 60, 110, 10));

        jLabel9.setFont(new java.awt.Font("Tahoma", 1, 11)); // NOI18N
        jLabel9.setForeground(new java.awt.Color(255, 255, 255));
        jLabel9.setText("Operating System Type : ");
        SystemInformation.add(jLabel9, new org.netbeans.lib.awtextra.AbsoluteConstraints(10, 90, -1, -1));

        jLabel10.setForeground(new java.awt.Color(255, 255, 255));
        String os_type = System.getProperty("os.arch");
        jLabel10.setText(os_type);
        SystemInformation.add(jLabel10, new org.netbeans.lib.awtextra.AbsoluteConstraints(160, 90, 80, -1));

        jLabel18.setFont(new java.awt.Font("Tahoma", 1, 11)); // NOI18N
        jLabel18.setForeground(new java.awt.Color(255, 255, 255));
        jLabel18.setText("Operating System Version :");
        SystemInformation.add(jLabel18, new org.netbeans.lib.awtextra.AbsoluteConstraints(10, 120, -1, -1));

        jLabel19.setForeground(new java.awt.Color(255, 255, 255));
        String OSVersion = System.getProperty("os.version");
        jLabel19.setText(OSVersion);
        SystemInformation.add(jLabel19, new org.netbeans.lib.awtextra.AbsoluteConstraints(168, 120, 70, -1));

        jLabel33.setFont(new java.awt.Font("Segoe UI", 1, 14)); // NOI18N
        jLabel33.setForeground(new java.awt.Color(255, 255, 255));
        jLabel33.setText("System Information");
        SystemInformation.add(jLabel33, new org.netbeans.lib.awtextra.AbsoluteConstraints(10, 10, -1, -1));

        jLabel7.setFont(new java.awt.Font("Segoe UI", 0, 14)); // NOI18N
        jLabel7.setText("    Detectify is a free file, hash and URL scanning system based on VirusTotal.  ");
        jLabel7.setVerticalAlignment(javax.swing.SwingConstants.TOP);

        jLabel14.setFont(new java.awt.Font("Segoe UI", 1, 24)); // NOI18N
        jLabel14.setForeground(new java.awt.Color(54, 33, 89));
        jLabel14.setText("How it works?");

        jLabel15.setFont(new java.awt.Font("Segoe UI", 0, 14)); // NOI18N
        jLabel15.setText("    Detectify is using Public API of VirusTotal. The API lets us upload and scan files, ");

        jLabel16.setFont(new java.awt.Font("Segoe UI", 0, 14)); // NOI18N
        jLabel16.setText("URLs, access finished scan reports and make automatic comments without the");

        jLabel17.setFont(new java.awt.Font("Segoe UI", 0, 14)); // NOI18N
        jLabel17.setText(" need of using the website interface.");

        jLabel21.setText(java.time.LocalDate.now().toString());

        jLabel13.setFont(new java.awt.Font("Segoe UI", 1, 24)); // NOI18N
        jLabel13.setForeground(new java.awt.Color(54, 33, 89));
        jLabel13.setText("What is Detectify?");

        javax.swing.GroupLayout HomePanelLayout = new javax.swing.GroupLayout(HomePanel);
        HomePanel.setLayout(HomePanelLayout);
        HomePanelLayout.setHorizontalGroup(
            HomePanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(HomePanelLayout.createSequentialGroup()
                .addGroup(HomePanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(HomePanelLayout.createSequentialGroup()
                        .addContainerGap()
                        .addGroup(HomePanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel13)
                            .addComponent(jLabel17)
                            .addComponent(jLabel12, javax.swing.GroupLayout.PREFERRED_SIZE, 457, javax.swing.GroupLayout.PREFERRED_SIZE)))
                    .addComponent(jLabel15, javax.swing.GroupLayout.PREFERRED_SIZE, 525, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 2908, Short.MAX_VALUE)
                .addComponent(jLabel21)
                .addGap(591, 591, 591))
            .addGroup(HomePanelLayout.createSequentialGroup()
                .addGroup(HomePanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(HomePanelLayout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(jLabel16))
                    .addGroup(HomePanelLayout.createSequentialGroup()
                        .addGroup(HomePanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel7, javax.swing.GroupLayout.PREFERRED_SIZE, 477, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addGroup(HomePanelLayout.createSequentialGroup()
                                .addContainerGap()
                                .addComponent(jLabel14)))
                        .addGap(45, 45, 45)
                        .addComponent(SystemInformation, javax.swing.GroupLayout.PREFERRED_SIZE, 254, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        HomePanelLayout.setVerticalGroup(
            HomePanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(HomePanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(HomePanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(SystemInformation, javax.swing.GroupLayout.PREFERRED_SIZE, 164, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(HomePanelLayout.createSequentialGroup()
                        .addComponent(jLabel13)
                        .addGap(18, 18, 18)
                        .addComponent(jLabel7, javax.swing.GroupLayout.PREFERRED_SIZE, 18, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGroup(HomePanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(HomePanelLayout.createSequentialGroup()
                                .addGap(161, 161, 161)
                                .addComponent(jLabel21))
                            .addGroup(HomePanelLayout.createSequentialGroup()
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(jLabel12, javax.swing.GroupLayout.PREFERRED_SIZE, 19, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(18, 18, 18)
                                .addComponent(jLabel14)
                                .addGap(18, 18, 18)
                                .addComponent(jLabel15)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(jLabel16)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(jLabel17)))))
                .addContainerGap(2146, Short.MAX_VALUE))
        );

        Pannels.add(HomePanel, "card3");

        ScanPanel.setBackground(new java.awt.Color(255, 255, 255));
        ScanPanel.setPreferredSize(new java.awt.Dimension(1532, 653));

        ScanChooseBoxes.setBackground(new java.awt.Color(255, 255, 255));

        URL.setBackground(new java.awt.Color(247, 247, 247));
        URL.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                URLMouseEntered(evt);
            }
            public void mouseExited(java.awt.event.MouseEvent evt) {
                URLMouseExited(evt);
            }
            public void mousePressed(java.awt.event.MouseEvent evt) {
                URLMousePressed(evt);
            }
        });
        URL.setLayout(null);

        jLabel26.setFont(new java.awt.Font("Segoe UI", 1, 14)); // NOI18N
        jLabel26.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel26.setText("URL");
        URL.add(jLabel26);
        jLabel26.setBounds(10, 10, 210, 30);

        jLabel31.setFont(new java.awt.Font("Tahoma", 0, 48)); // NOI18N
        jLabel31.setForeground(new java.awt.Color(54, 33, 89));
        jLabel31.setText("_________");
        jLabel31.setVisible(false);
        URL.add(jLabel31);
        jLabel31.setBounds(0, 0, 250, 58);

        FILE.setBackground(new java.awt.Color(247, 247, 247));
        FILE.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                FILEMouseEntered(evt);
            }
            public void mouseExited(java.awt.event.MouseEvent evt) {
                FILEMouseExited(evt);
            }
            public void mousePressed(java.awt.event.MouseEvent evt) {
                FILEMousePressed(evt);
            }
        });
        FILE.setLayout(null);

        jLabel25.setBackground(new java.awt.Color(255, 255, 255));
        jLabel25.setFont(new java.awt.Font("Segoe UI", 1, 14)); // NOI18N
        jLabel25.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel25.setText("FILE");
        FILE.add(jLabel25);
        jLabel25.setBounds(0, 10, 220, 28);

        jLabel29.setFont(new java.awt.Font("Tahoma", 0, 48)); // NOI18N
        jLabel29.setForeground(new java.awt.Color(54, 33, 89));
        jLabel29.setText("_________");
        FILE.add(jLabel29);
        jLabel29.setBounds(-20, 0, 250, 58);

        javax.swing.GroupLayout ScanChooseBoxesLayout = new javax.swing.GroupLayout(ScanChooseBoxes);
        ScanChooseBoxes.setLayout(ScanChooseBoxesLayout);
        ScanChooseBoxesLayout.setHorizontalGroup(
            ScanChooseBoxesLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(ScanChooseBoxesLayout.createSequentialGroup()
                .addGap(162, 162, 162)
                .addComponent(FILE, javax.swing.GroupLayout.PREFERRED_SIZE, 216, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(URL, javax.swing.GroupLayout.PREFERRED_SIZE, 220, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(3420, Short.MAX_VALUE))
        );
        ScanChooseBoxesLayout.setVerticalGroup(
            ScanChooseBoxesLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, ScanChooseBoxesLayout.createSequentialGroup()
                .addGap(0, 0, Short.MAX_VALUE)
                .addGroup(ScanChooseBoxesLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(URL, javax.swing.GroupLayout.PREFERRED_SIZE, 59, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(FILE, javax.swing.GroupLayout.PREFERRED_SIZE, 73, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(119, 119, 119))
        );

        ScanContent.setBackground(new java.awt.Color(255, 255, 255));
        ScanContent.setLayout(new java.awt.CardLayout());

        FilePanel.setVisible(false);
        FilePanel.setBackground(new java.awt.Color(255, 255, 255));
        FilePanel.setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

        Border border = BorderFactory.createDashedBorder(Color.BLACK, 2f, 2f, 2f, false);
        jPanel12.setBorder(border);
        jPanel12.setBackground(new java.awt.Color(247, 247, 247));

        DragAndDrop.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        DragAndDrop.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/icons8-plus-64.png"))); // NOI18N

        jLabel27.setFont(new java.awt.Font("Segoe UI", 0, 12)); // NOI18N
        jLabel27.setText("Drag and drop file here");

        jLabel28.setFont(new java.awt.Font("Segoe UI", 0, 12)); // NOI18N
        jLabel28.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel28.setText("or");

        jButton1.setBackground(new java.awt.Color(255, 255, 255));
        jButton1.setFont(new java.awt.Font("Segoe UI", 0, 12)); // NOI18N
        jButton1.setText("Choose file");
        jButton1.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                jButton1MouseEntered(evt);
            }
            public void mouseExited(java.awt.event.MouseEvent evt) {
                jButton1MouseExited(evt);
            }
            public void mousePressed(java.awt.event.MouseEvent evt) {
                jButton1MousePressed(evt);
            }
        });

        jLabel34.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/icons8-x-men-10.png"))); // NOI18N
        jLabel34.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                jLabel34MouseEntered(evt);
            }
            public void mouseExited(java.awt.event.MouseEvent evt) {
                jLabel34MouseExited(evt);
            }
            public void mousePressed(java.awt.event.MouseEvent evt) {
                jLabel34MousePressed(evt);
            }
        });

        jLabel32.setText("FileName");

        FileName.setVisible(false);

        javax.swing.GroupLayout FileNameLayout = new javax.swing.GroupLayout(FileName);
        FileName.setLayout(FileNameLayout);
        FileNameLayout.setHorizontalGroup(
            FileNameLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(FileNameLayout.createSequentialGroup()
                .addComponent(jLabel32, javax.swing.GroupLayout.PREFERRED_SIZE, 105, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(6, 6, 6)
                .addComponent(jLabel34, javax.swing.GroupLayout.PREFERRED_SIZE, 14, javax.swing.GroupLayout.PREFERRED_SIZE))
        );
        FileNameLayout.setVerticalGroup(
            FileNameLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jLabel32, javax.swing.GroupLayout.PREFERRED_SIZE, 23, javax.swing.GroupLayout.PREFERRED_SIZE)
            .addComponent(jLabel34, javax.swing.GroupLayout.PREFERRED_SIZE, 23, javax.swing.GroupLayout.PREFERRED_SIZE)
        );

        javax.swing.GroupLayout jPanel12Layout = new javax.swing.GroupLayout(jPanel12);
        jPanel12.setLayout(jPanel12Layout);
        jPanel12Layout.setHorizontalGroup(
            jPanel12Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel12Layout.createSequentialGroup()
                .addGroup(jPanel12Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel12Layout.createSequentialGroup()
                        .addGap(10, 10, 10)
                        .addComponent(DragAndDrop, javax.swing.GroupLayout.PREFERRED_SIZE, 310, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(jPanel12Layout.createSequentialGroup()
                        .addGap(101, 101, 101)
                        .addComponent(jLabel28, javax.swing.GroupLayout.PREFERRED_SIZE, 125, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(jPanel12Layout.createSequentialGroup()
                        .addGap(100, 100, 100)
                        .addGroup(jPanel12Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(FileName, javax.swing.GroupLayout.PREFERRED_SIZE, 124, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jButton1, javax.swing.GroupLayout.PREFERRED_SIZE, 125, javax.swing.GroupLayout.PREFERRED_SIZE)))
                    .addGroup(jPanel12Layout.createSequentialGroup()
                        .addGap(101, 101, 101)
                        .addComponent(jLabel27, javax.swing.GroupLayout.PREFERRED_SIZE, 139, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        jPanel12Layout.setVerticalGroup(
            jPanel12Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel12Layout.createSequentialGroup()
                .addGap(11, 11, 11)
                .addComponent(DragAndDrop, javax.swing.GroupLayout.PREFERRED_SIZE, 76, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(6, 6, 6)
                .addComponent(jLabel27)
                .addGap(6, 6, 6)
                .addComponent(jLabel28)
                .addGap(6, 6, 6)
                .addComponent(FileName, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(10, 10, 10)
                .addComponent(jButton1, javax.swing.GroupLayout.PREFERRED_SIZE, 34, javax.swing.GroupLayout.PREFERRED_SIZE))
        );

        FilePanel.add(jPanel12, new org.netbeans.lib.awtextra.AbsoluteConstraints(45, 0, -1, 208));

        jPanel13.setBackground(new java.awt.Color(247, 247, 247));
        jPanel13.setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

        NameLabel.setFont(new java.awt.Font("Segoe UI", 1, 12)); // NOI18N
        NameLabel.setText("File Name :");
        jPanel13.add(NameLabel, new org.netbeans.lib.awtextra.AbsoluteConstraints(10, 20, 70, 29));

        fileName.setText("There is no file selected!");
        jPanel13.add(fileName, new org.netbeans.lib.awtextra.AbsoluteConstraints(80, 20, 200, 30));

        PathLabel.setFont(new java.awt.Font("Segoe UI", 1, 12)); // NOI18N
        PathLabel.setText("File Path :");
        jPanel13.add(PathLabel, new org.netbeans.lib.awtextra.AbsoluteConstraints(10, 51, 70, 31));
        jPanel13.add(filePath, new org.netbeans.lib.awtextra.AbsoluteConstraints(70, 50, 290, 31));

        FSizeLabel.setFont(new java.awt.Font("Segoe UI", 1, 12)); // NOI18N
        FSizeLabel.setText("File Size :");
        jPanel13.add(FSizeLabel, new org.netbeans.lib.awtextra.AbsoluteConstraints(10, 93, -1, -1));
        jPanel13.add(FileSize, new org.netbeans.lib.awtextra.AbsoluteConstraints(70, 90, 130, 20));

        FExtensionLabel.setFont(new java.awt.Font("Segoe UI", 1, 12)); // NOI18N
        FExtensionLabel.setText("File Extension :");
        jPanel13.add(FExtensionLabel, new org.netbeans.lib.awtextra.AbsoluteConstraints(10, 127, -1, -1));
        jPanel13.add(fileExtension, new org.netbeans.lib.awtextra.AbsoluteConstraints(98, 127, -1, -1));

        StatusPanel.setBackground(new java.awt.Color(247, 247, 247));

        Status.setFont(new java.awt.Font("Segoe UI", 1, 11)); // NOI18N
        Status.setHorizontalAlignment(javax.swing.SwingConstants.LEFT);
        Status.setText("You can scan a file with size at most 32 MB!");

        StatusIcon.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/icons8-checkmark-15.png"))); // NOI18N
        StatusIcon.setVisible(false);

        javax.swing.GroupLayout StatusPanelLayout = new javax.swing.GroupLayout(StatusPanel);
        StatusPanel.setLayout(StatusPanelLayout);
        StatusPanelLayout.setHorizontalGroup(
            StatusPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, StatusPanelLayout.createSequentialGroup()
                .addComponent(StatusIcon)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(Status, javax.swing.GroupLayout.DEFAULT_SIZE, 259, Short.MAX_VALUE))
        );
        StatusPanelLayout.setVerticalGroup(
            StatusPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(Status, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
            .addGroup(StatusPanelLayout.createSequentialGroup()
                .addGap(0, 0, Short.MAX_VALUE)
                .addComponent(StatusIcon, javax.swing.GroupLayout.PREFERRED_SIZE, 26, javax.swing.GroupLayout.PREFERRED_SIZE))
        );

        jPanel13.add(StatusPanel, new org.netbeans.lib.awtextra.AbsoluteConstraints(10, 170, 280, -1));

        FilePanel.add(jPanel13, new org.netbeans.lib.awtextra.AbsoluteConstraints(380, 0, -1, 208));

        ScanButton.setBackground(new java.awt.Color(54, 33, 89));
        ScanButton.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mousePressed(java.awt.event.MouseEvent evt) {
                ScanButtonMousePressed(evt);
            }
        });
        ScanButton.setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

        Scan.setFont(new java.awt.Font("Segoe UI", 0, 14)); // NOI18N
        Scan.setForeground(new java.awt.Color(255, 255, 255));
        Scan.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        Scan.setText("SCAN");
        Scan.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                ScanMouseEntered(evt);
            }
            public void mouseExited(java.awt.event.MouseEvent evt) {
                ScanMouseExited(evt);
            }
            public void mousePressed(java.awt.event.MouseEvent evt) {
                ScanMousePressed(evt);
            }
        });
        ScanButton.add(Scan, new org.netbeans.lib.awtextra.AbsoluteConstraints(0, 0, 177, 39));

        FilePanel.add(ScanButton, new org.netbeans.lib.awtextra.AbsoluteConstraints(297, 226, -1, -1));

        ScanContent.add(FilePanel, "card3");

        URLPanel.setVisible(false);
        URLPanel.setBackground(new java.awt.Color(255, 255, 255));

        URLTf.setForeground(new java.awt.Color(153, 153, 153));
        URLTf.setText("Search or scan a URL");
        URLTf.setBorder(javax.swing.BorderFactory.createMatteBorder(0, 0, 2, 0, new java.awt.Color(54, 33, 89)));
        URLTf.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mousePressed(java.awt.event.MouseEvent evt) {
                URLTfMousePressed(evt);
            }
        });
        URLTf.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                URLTfActionPerformed(evt);
            }
        });

        SearchButton.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        SearchButton.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/icons8-search-15.png"))); // NOI18N
        SearchButton.setBorder(javax.swing.BorderFactory.createMatteBorder(0, 0, 2, 0, new java.awt.Color(54, 33, 89)));
        SearchButton.setPreferredSize(new java.awt.Dimension(40, 18));
        SearchButton.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                SearchButtonMouseEntered(evt);
            }
            public void mouseExited(java.awt.event.MouseEvent evt) {
                SearchButtonMouseExited(evt);
            }
            public void mousePressed(java.awt.event.MouseEvent evt) {
                SearchButtonMousePressed(evt);
            }
        });

        WWWLogo.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/icons8-website-64.png"))); // NOI18N

        javax.swing.GroupLayout URLPanelLayout = new javax.swing.GroupLayout(URLPanel);
        URLPanel.setLayout(URLPanelLayout);
        URLPanelLayout.setHorizontalGroup(
            URLPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(URLPanelLayout.createSequentialGroup()
                .addGroup(URLPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(URLPanelLayout.createSequentialGroup()
                        .addGap(338, 338, 338)
                        .addComponent(WWWLogo))
                    .addGroup(URLPanelLayout.createSequentialGroup()
                        .addGap(145, 145, 145)
                        .addComponent(URLTf, javax.swing.GroupLayout.PREFERRED_SIZE, 402, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(SearchButton, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(165, Short.MAX_VALUE))
        );
        URLPanelLayout.setVerticalGroup(
            URLPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(URLPanelLayout.createSequentialGroup()
                .addGap(31, 31, 31)
                .addComponent(WWWLogo)
                .addGap(32, 32, 32)
                .addGroup(URLPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(URLTf, javax.swing.GroupLayout.PREFERRED_SIZE, 40, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(SearchButton, javax.swing.GroupLayout.PREFERRED_SIZE, 40, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(126, Short.MAX_VALUE))
        );

        ScanContent.add(URLPanel, "card2");

        javax.swing.GroupLayout ScanPanelLayout = new javax.swing.GroupLayout(ScanPanel);
        ScanPanel.setLayout(ScanPanelLayout);
        ScanPanelLayout.setHorizontalGroup(
            ScanPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(ScanChooseBoxes, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
            .addGroup(ScanPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(ScanContent, javax.swing.GroupLayout.PREFERRED_SIZE, 756, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(0, 0, Short.MAX_VALUE))
        );
        ScanPanelLayout.setVerticalGroup(
            ScanPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(ScanPanelLayout.createSequentialGroup()
                .addComponent(ScanChooseBoxes, javax.swing.GroupLayout.PREFERRED_SIZE, 58, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(ScanContent, javax.swing.GroupLayout.PREFERRED_SIZE, 293, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap())
        );

        Pannels.add(ScanPanel, "card2");

        ScannedPanel.setBackground(new java.awt.Color(255, 255, 255));

        jLabel1.setText("jLabel1");

        DatabaseData.setBackground(new java.awt.Color(250, 250, 250));

        jTable1.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {

            },
            new String [] {
                "id", "Name", "Type", "Scan ID", "Scan Date", "Delete", "Detail"
            }
        ) {
            boolean[] canEdit = new boolean [] {
                false, false, false, false, false, false, false
            };

            public boolean isCellEditable(int rowIndex, int columnIndex) {
                return canEdit [columnIndex];
            }
        });
        jTable1.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                jTable1MouseClicked(evt);
            }
        });
        DatabaseData.setViewportView(jTable1);
        if (jTable1.getColumnModel().getColumnCount() > 0) {
            jTable1.getColumnModel().getColumn(0).setHeaderValue("id");
            jTable1.getColumnModel().getColumn(1).setHeaderValue("Name");
            jTable1.getColumnModel().getColumn(2).setHeaderValue("Type");
            jTable1.getColumnModel().getColumn(3).setHeaderValue("Scan ID");
            jTable1.getColumnModel().getColumn(4).setHeaderValue("Scan Date");
            jTable1.getColumnModel().getColumn(5).setHeaderValue("Delete");
            jTable1.getColumnModel().getColumn(6).setHeaderValue("Detail");
        }

        javax.swing.GroupLayout ScannedPanelLayout = new javax.swing.GroupLayout(ScannedPanel);
        ScannedPanel.setLayout(ScannedPanelLayout);
        ScannedPanelLayout.setHorizontalGroup(
            ScannedPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(ScannedPanelLayout.createSequentialGroup()
                .addGroup(ScannedPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(ScannedPanelLayout.createSequentialGroup()
                        .addGap(181, 181, 181)
                        .addComponent(jLabel1))
                    .addGroup(ScannedPanelLayout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(DatabaseData, javax.swing.GroupLayout.PREFERRED_SIZE, 771, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(3243, Short.MAX_VALUE))
        );
        ScannedPanelLayout.setVerticalGroup(
            ScannedPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(ScannedPanelLayout.createSequentialGroup()
                .addComponent(DatabaseData, javax.swing.GroupLayout.PREFERRED_SIZE, 337, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(692, 692, 692)
                .addComponent(jLabel1)
                .addContainerGap(1347, Short.MAX_VALUE))
        );

        Pannels.add(ScannedPanel, "card4");

        SettingsPanel.setBackground(new java.awt.Color(255, 255, 255));
        SettingsPanel.setForeground(new java.awt.Color(255, 255, 255));
        SettingsPanel.setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

        SettingContent.setBackground(new java.awt.Color(255, 255, 255));

        jLabel2.setFont(new java.awt.Font("Segoe UI", 1, 14)); // NOI18N
        jLabel2.setText("Change API key:");

        apiKeyText.setText(" ");

        jLabel11.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/warning.png"))); // NOI18N
        jLabel11.setText("Warning this key is using during your file scanning operations.");

        SaveButton.setText("Save");
        SaveButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                SaveButtonActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout SettingContentLayout = new javax.swing.GroupLayout(SettingContent);
        SettingContent.setLayout(SettingContentLayout);
        SettingContentLayout.setHorizontalGroup(
            SettingContentLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(SettingContentLayout.createSequentialGroup()
                .addGap(35, 35, 35)
                .addGroup(SettingContentLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(ApiKeyStatus)
                    .addComponent(jLabel11, javax.swing.GroupLayout.PREFERRED_SIZE, 427, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(SettingContentLayout.createSequentialGroup()
                        .addComponent(apiKeyText, javax.swing.GroupLayout.PREFERRED_SIZE, 354, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(SaveButton, javax.swing.GroupLayout.PREFERRED_SIZE, 72, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addComponent(jLabel2, javax.swing.GroupLayout.PREFERRED_SIZE, 220, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(63, Short.MAX_VALUE))
        );
        SettingContentLayout.setVerticalGroup(
            SettingContentLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(SettingContentLayout.createSequentialGroup()
                .addGap(28, 28, 28)
                .addComponent(jLabel2, javax.swing.GroupLayout.PREFERRED_SIZE, 37, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(SettingContentLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(apiKeyText, javax.swing.GroupLayout.PREFERRED_SIZE, 35, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(SaveButton, javax.swing.GroupLayout.PREFERRED_SIZE, 35, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(16, 16, 16)
                .addComponent(ApiKeyStatus)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel11, javax.swing.GroupLayout.PREFERRED_SIZE, 22, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(140, Short.MAX_VALUE))
        );

        SettingsPanel.add(SettingContent, new org.netbeans.lib.awtextra.AbsoluteConstraints(120, 30, 530, 290));

        Pannels.add(SettingsPanel, "card5");

        ResultPanel6.setBackground(new java.awt.Color(255, 255, 255));
        ResultPanel6.setPreferredSize(new java.awt.Dimension(792, 1200));
        ResultPanel6.setLayout(new GridLayout(0,1));

        javax.swing.GroupLayout ResultPanel6Layout = new javax.swing.GroupLayout(ResultPanel6);
        ResultPanel6.setLayout(ResultPanel6Layout);
        ResultPanel6Layout.setHorizontalGroup(
            ResultPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 792, Short.MAX_VALUE)
        );
        ResultPanel6Layout.setVerticalGroup(
            ResultPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 1200, Short.MAX_VALUE)
        );

        jScrollPane1.setViewportView(ResultPanel6);

        javax.swing.GroupLayout ResultPanelLayout = new javax.swing.GroupLayout(ResultPanel);
        ResultPanel.setLayout(ResultPanelLayout);
        ResultPanelLayout.setHorizontalGroup(
            ResultPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(ResultPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 770, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(3244, Short.MAX_VALUE))
        );
        ResultPanelLayout.setVerticalGroup(
            ResultPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(ResultPanelLayout.createSequentialGroup()
                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 358, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(0, 2032, Short.MAX_VALUE))
        );

        Pannels.add(ResultPanel, "card6");

        AboutPanel.setBackground(new java.awt.Color(255, 255, 255));

        jLabel30.setFont(new java.awt.Font("Tahoma", 0, 14)); // NOI18N
        jLabel30.setText("Detectify is a free file, hash and URL scanning system based on VirusTotal.");

        jLabel22.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/logo.png"))); // NOI18N

        jLabel24.setFont(new java.awt.Font("Tahoma", 0, 14)); // NOI18N
        jLabel24.setText("This project also has been developed as part of CENG201 Projects.");

        jLabel43.setFont(new java.awt.Font("Segoe UI", 1, 18)); // NOI18N
        jLabel43.setText("OPEN SOURCE");

        jLabel46.setFont(new java.awt.Font("Segoe UI", 1, 18)); // NOI18N
        jLabel46.setText("THANKS TO");

        jLabel48.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/vt_1.png"))); // NOI18N

        javax.swing.GroupLayout AboutPanelLayout = new javax.swing.GroupLayout(AboutPanel);
        AboutPanel.setLayout(AboutPanelLayout);
        AboutPanelLayout.setHorizontalGroup(
            AboutPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(AboutPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel22)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(AboutPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(AboutPanelLayout.createSequentialGroup()
                        .addGap(16, 16, 16)
                        .addComponent(jLabel30)
                        .addGap(0, 0, Short.MAX_VALUE))
                    .addGroup(AboutPanelLayout.createSequentialGroup()
                        .addGroup(AboutPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel43)
                            .addComponent(jLabel24)
                            .addComponent(jLabel46)
                            .addComponent(jLabel48))
                        .addContainerGap(3396, Short.MAX_VALUE))))
        );
        AboutPanelLayout.setVerticalGroup(
            AboutPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(AboutPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(AboutPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addGroup(AboutPanelLayout.createSequentialGroup()
                        .addComponent(jLabel43)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jLabel30)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jLabel24)
                        .addGap(18, 18, 18)
                        .addComponent(jLabel46)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(jLabel48))
                    .addComponent(jLabel22))
                .addContainerGap(2201, Short.MAX_VALUE))
        );

        Pannels.add(AboutPanel, "card5");

        StableBig.setLayout(new java.awt.CardLayout());

        Stable.setBackground(new java.awt.Color(255, 255, 255));
        Stable.setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

        jLabel6.setFont(new java.awt.Font("Segoe UI", 0, 36)); // NOI18N
        jLabel6.setForeground(new java.awt.Color(54, 33, 89));
        jLabel6.setText("HOME");
        Stable.add(jLabel6, new org.netbeans.lib.awtextra.AbsoluteConstraints(10, 0, -1, -1));

        jLabel8.setFont(new java.awt.Font("Tahoma", 1, 18)); // NOI18N
        jLabel8.setText("_________________________________________________________________________");
        Stable.add(jLabel8, new org.netbeans.lib.awtextra.AbsoluteConstraints(0, 51, -1, -1));

        StableBig.add(Stable, "card3");

        ResultPanelStable.setBackground(new java.awt.Color(255, 255, 255));
        ResultPanelStable.setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());
        ResultPanelStable.setVisible(false);

        FileNameLabel.setText("File Name");
        ResultPanelStable.add(FileNameLabel, new org.netbeans.lib.awtextra.AbsoluteConstraints(140, 60, -1, -1));

        ExtensionLabel.setText("Extension");
        ResultPanelStable.add(ExtensionLabel, new org.netbeans.lib.awtextra.AbsoluteConstraints(610, 50, 50, 20));

        jPanel3.setBackground(new java.awt.Color(250, 250, 250));
        jPanel3.setBorder(javax.swing.BorderFactory.createMatteBorder(2, 2, 2, 2, new java.awt.Color(0, 102, 0)));

        jLabel37.setFont(new java.awt.Font("Segoe UI", 1, 36)); // NOI18N
        jLabel37.setForeground(new java.awt.Color(0, 102, 0));
        jLabel37.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel37.setText("0");

        TotalCount.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        TotalCount.setText("TotalCount");

        javax.swing.GroupLayout jPanel3Layout = new javax.swing.GroupLayout(jPanel3);
        jPanel3.setLayout(jPanel3Layout);
        jPanel3Layout.setHorizontalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jLabel37, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
            .addComponent(TotalCount, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 122, Short.MAX_VALUE)
        );
        jPanel3Layout.setVerticalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel3Layout.createSequentialGroup()
                .addGap(12, 12, 12)
                .addComponent(jLabel37, javax.swing.GroupLayout.PREFERRED_SIZE, 30, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(TotalCount, javax.swing.GroupLayout.PREFERRED_SIZE, 14, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(0, 0, Short.MAX_VALUE))
        );

        ResultPanelStable.add(jPanel3, new org.netbeans.lib.awtextra.AbsoluteConstraints(0, 0, -1, 78));

        HashLabel.setText("jLabel45");
        ResultPanelStable.add(HashLabel, new org.netbeans.lib.awtextra.AbsoluteConstraints(140, 40, -1, -1));

        SizeLabel.setText("SizeLabel");
        ResultPanelStable.add(SizeLabel, new org.netbeans.lib.awtextra.AbsoluteConstraints(470, 50, -1, 20));

        jLabel38.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/icons8-vertical-line-25.png"))); // NOI18N
        ResultPanelStable.add(jLabel38, new org.netbeans.lib.awtextra.AbsoluteConstraints(450, 30, 20, 40));

        jLabel40.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/icons8-vertical-line-25.png"))); // NOI18N
        ResultPanelStable.add(jLabel40, new org.netbeans.lib.awtextra.AbsoluteConstraints(590, 30, 20, 40));

        jLabel41.setFont(new java.awt.Font("Segoe UI", 0, 11)); // NOI18N
        jLabel41.setText("Size");
        ResultPanelStable.add(jLabel41, new org.netbeans.lib.awtextra.AbsoluteConstraints(470, 30, -1, -1));

        StatusLabel.setText("jLabel44");

        jLabel42.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/icons8-checkmark-15.png"))); // NOI18N

        jLabel36.setFont(new java.awt.Font("Tahoma", 0, 14)); // NOI18N
        jLabel36.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel36.setText("Full Report");
        jLabel36.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                jLabel36MouseEntered(evt);
            }
            public void mouseExited(java.awt.event.MouseEvent evt) {
                jLabel36MouseExited(evt);
            }
            public void mousePressed(java.awt.event.MouseEvent evt) {
                jLabel36MousePressed(evt);
            }
        });

        javax.swing.GroupLayout jPanel15Layout = new javax.swing.GroupLayout(jPanel15);
        jPanel15.setLayout(jPanel15Layout);
        jPanel15Layout.setHorizontalGroup(
            jPanel15Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel15Layout.createSequentialGroup()
                .addComponent(StatusLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel42)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 479, Short.MAX_VALUE)
                .addComponent(jLabel36, javax.swing.GroupLayout.PREFERRED_SIZE, 80, javax.swing.GroupLayout.PREFERRED_SIZE))
        );
        jPanel15Layout.setVerticalGroup(
            jPanel15Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel15Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                .addComponent(StatusLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 30, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addComponent(jLabel42, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
            .addGroup(jPanel15Layout.createSequentialGroup()
                .addComponent(jLabel36)
                .addGap(0, 0, Short.MAX_VALUE))
        );

        ResultPanelStable.add(jPanel15, new org.netbeans.lib.awtextra.AbsoluteConstraints(140, 0, 620, -1));

        FileTypeLabel.setText("File type");
        ResultPanelStable.add(FileTypeLabel, new org.netbeans.lib.awtextra.AbsoluteConstraints(610, 30, 50, -1));

        StableBig.add(ResultPanelStable, "card2");

        ScannedFilesStable.setBackground(new java.awt.Color(255, 255, 255));
        ScannedFilesStable.setPreferredSize(new java.awt.Dimension(840, 73));

        ScannedFilesInfoBoxes.setBackground(new java.awt.Color(255, 255, 255));

        AllTotal.setBackground(new java.awt.Color(54, 33, 89));
        AllTotal.setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

        jLabel39.setFont(new java.awt.Font("Segoe UI", 0, 11)); // NOI18N
        jLabel39.setForeground(new java.awt.Color(255, 255, 255));
        jLabel39.setText("Total Scanned Files and URLs");
        AllTotal.add(jLabel39, new org.netbeans.lib.awtextra.AbsoluteConstraints(95, 38, -1, -1));

        jPanel18.setBackground(new java.awt.Color(64, 43, 100));

        jLabel45.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/icons8-sigma-15.png"))); // NOI18N

        javax.swing.GroupLayout jPanel18Layout = new javax.swing.GroupLayout(jPanel18);
        jPanel18.setLayout(jPanel18Layout);
        jPanel18Layout.setHorizontalGroup(
            jPanel18Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel18Layout.createSequentialGroup()
                .addGap(31, 31, 31)
                .addComponent(jLabel45)
                .addContainerGap(39, Short.MAX_VALUE))
        );
        jPanel18Layout.setVerticalGroup(
            jPanel18Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel18Layout.createSequentialGroup()
                .addGap(21, 21, 21)
                .addComponent(jLabel45)
                .addContainerGap(28, Short.MAX_VALUE))
        );

        AllTotal.add(jPanel18, new org.netbeans.lib.awtextra.AbsoluteConstraints(0, 0, -1, -1));

        TotalAll.setFont(new java.awt.Font("Segoe UI", 0, 14)); // NOI18N
        TotalAll.setForeground(new java.awt.Color(255, 255, 255));
        TotalAll.setText("0");
        AllTotal.add(TotalAll, new org.netbeans.lib.awtextra.AbsoluteConstraints(95, 12, -1, -1));

        FilesTotal.setBackground(new java.awt.Color(54, 33, 89));
        FilesTotal.setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

        jLabel49.setFont(new java.awt.Font("Segoe UI", 0, 11)); // NOI18N
        jLabel49.setForeground(new java.awt.Color(255, 255, 255));
        jLabel49.setText("Total Scanned Files");
        FilesTotal.add(jLabel49, new org.netbeans.lib.awtextra.AbsoluteConstraints(95, 38, 144, -1));

        jPanel22.setBackground(new java.awt.Color(64, 43, 100));

        jLabel50.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/icons8-file-15.png"))); // NOI18N

        javax.swing.GroupLayout jPanel22Layout = new javax.swing.GroupLayout(jPanel22);
        jPanel22.setLayout(jPanel22Layout);
        jPanel22Layout.setHorizontalGroup(
            jPanel22Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel22Layout.createSequentialGroup()
                .addGap(31, 31, 31)
                .addComponent(jLabel50)
                .addContainerGap(39, Short.MAX_VALUE))
        );
        jPanel22Layout.setVerticalGroup(
            jPanel22Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel22Layout.createSequentialGroup()
                .addGap(21, 21, 21)
                .addComponent(jLabel50)
                .addContainerGap(28, Short.MAX_VALUE))
        );

        FilesTotal.add(jPanel22, new org.netbeans.lib.awtextra.AbsoluteConstraints(0, 0, -1, -1));

        TotalFiles.setFont(new java.awt.Font("Segoe UI", 0, 14)); // NOI18N
        TotalFiles.setForeground(new java.awt.Color(255, 255, 255));
        TotalFiles.setText("0");
        FilesTotal.add(TotalFiles, new org.netbeans.lib.awtextra.AbsoluteConstraints(95, 12, -1, -1));

        URLTotal.setBackground(new java.awt.Color(54, 33, 89));
        URLTotal.setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

        jLabel52.setFont(new java.awt.Font("Segoe UI", 0, 11)); // NOI18N
        jLabel52.setForeground(new java.awt.Color(255, 255, 255));
        jLabel52.setText("Total Scanned URLs");
        URLTotal.add(jLabel52, new org.netbeans.lib.awtextra.AbsoluteConstraints(95, 38, 145, -1));

        jPanel24.setBackground(new java.awt.Color(64, 43, 100));

        jLabel53.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/websiteWhite15.png"))); // NOI18N

        javax.swing.GroupLayout jPanel24Layout = new javax.swing.GroupLayout(jPanel24);
        jPanel24.setLayout(jPanel24Layout);
        jPanel24Layout.setHorizontalGroup(
            jPanel24Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel24Layout.createSequentialGroup()
                .addGap(31, 31, 31)
                .addComponent(jLabel53)
                .addContainerGap(39, Short.MAX_VALUE))
        );
        jPanel24Layout.setVerticalGroup(
            jPanel24Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel24Layout.createSequentialGroup()
                .addGap(21, 21, 21)
                .addComponent(jLabel53)
                .addContainerGap(28, Short.MAX_VALUE))
        );

        URLTotal.add(jPanel24, new org.netbeans.lib.awtextra.AbsoluteConstraints(0, 0, -1, -1));

        TotalURLs.setFont(new java.awt.Font("Segoe UI", 0, 14)); // NOI18N
        TotalURLs.setForeground(new java.awt.Color(255, 255, 255));
        TotalURLs.setText("0");
        URLTotal.add(TotalURLs, new org.netbeans.lib.awtextra.AbsoluteConstraints(95, 12, -1, -1));

        javax.swing.GroupLayout ScannedFilesInfoBoxesLayout = new javax.swing.GroupLayout(ScannedFilesInfoBoxes);
        ScannedFilesInfoBoxes.setLayout(ScannedFilesInfoBoxesLayout);
        ScannedFilesInfoBoxesLayout.setHorizontalGroup(
            ScannedFilesInfoBoxesLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(ScannedFilesInfoBoxesLayout.createSequentialGroup()
                .addGap(6, 6, 6)
                .addComponent(AllTotal, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(FilesTotal, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(URLTotal, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(168, Short.MAX_VALUE))
        );
        ScannedFilesInfoBoxesLayout.setVerticalGroup(
            ScannedFilesInfoBoxesLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, ScannedFilesInfoBoxesLayout.createSequentialGroup()
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addGroup(ScannedFilesInfoBoxesLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(URLTotal, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(FilesTotal, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(AllTotal, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(81, 81, 81))
        );

        ScannedFilesStable.setVisible(false);

        javax.swing.GroupLayout ScannedFilesStableLayout = new javax.swing.GroupLayout(ScannedFilesStable);
        ScannedFilesStable.setLayout(ScannedFilesStableLayout);
        ScannedFilesStableLayout.setHorizontalGroup(
            ScannedFilesStableLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(ScannedFilesStableLayout.createSequentialGroup()
                .addComponent(ScannedFilesInfoBoxes, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(0, 0, Short.MAX_VALUE))
        );
        ScannedFilesStableLayout.setVerticalGroup(
            ScannedFilesStableLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, ScannedFilesStableLayout.createSequentialGroup()
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(ScannedFilesInfoBoxes, javax.swing.GroupLayout.PREFERRED_SIZE, 107, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(107, 107, 107))
        );

        StableBig.add(ScannedFilesStable, "card4");

        javax.swing.GroupLayout MainPanelLayout = new javax.swing.GroupLayout(MainPanel);
        MainPanel.setLayout(MainPanelLayout);
        MainPanelLayout.setHorizontalGroup(
            MainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(MainPanelLayout.createSequentialGroup()
                .addGroup(MainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(MainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                        .addComponent(Pannels, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGroup(javax.swing.GroupLayout.Alignment.LEADING, MainPanelLayout.createSequentialGroup()
                            .addComponent(CustomTitleBar, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addGap(828, 828, 828)))
                    .addComponent(StableBig, javax.swing.GroupLayout.PREFERRED_SIZE, 850, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        MainPanelLayout.setVerticalGroup(
            MainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(MainPanelLayout.createSequentialGroup()
                .addComponent(CustomTitleBar, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(StableBig, javax.swing.GroupLayout.PREFERRED_SIZE, 90, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(Pannels, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(372, 372, 372))
        );

        ContentPanel.add(MainPanel, "card3");

        GeneralPanel.add(ContentPanel);
        ContentPanel.setBounds(210, 0, 4109, 490);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(GeneralPanel, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 990, Short.MAX_VALUE)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(GeneralPanel, javax.swing.GroupLayout.PREFERRED_SIZE, 488, javax.swing.GroupLayout.PREFERRED_SIZE)
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents
    private void CloseLabelMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_CloseLabelMouseClicked
        ClosePanel.setBackground(new Color(192, 0, 0));
        System.exit(0);
        grafik();
    }//GEN-LAST:event_CloseLabelMouseClicked

    private void ScanButtonLabelMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_ScanButtonLabelMouseEntered
        grafik();
        ScanButtonPanel.setBackground(new Color(85, 65, 118));
        Cursor cursor = new Cursor(Cursor.HAND_CURSOR);
        setCursor(cursor);

    }//GEN-LAST:event_ScanButtonLabelMouseEntered

    private void ScannedButtonLabelMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_ScannedButtonLabelMouseEntered
        grafik();
        ScannedButtonPanel.setBackground(new Color(85, 65, 118));
        Cursor cursor = new Cursor(Cursor.HAND_CURSOR);
        setCursor(cursor);

    }//GEN-LAST:event_ScannedButtonLabelMouseEntered

    private void AboutButtonLabelMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_AboutButtonLabelMouseEntered
        grafik();
        AboutButtonPanel.setBackground(new Color(85, 65, 118));
        Cursor cursor = new Cursor(Cursor.HAND_CURSOR);
        setCursor(cursor);
    }//GEN-LAST:event_AboutButtonLabelMouseEntered

    private void ScanButtonLabelMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_ScanButtonLabelMouseExited
        ScanButtonPanel.setBackground(new Color(64, 43, 100));
        Cursor cursor = new Cursor(Cursor.DEFAULT_CURSOR);
        setCursor(cursor);
        grafik();

    }//GEN-LAST:event_ScanButtonLabelMouseExited

    private void HomeButtonLabelMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_HomeButtonLabelMouseExited
        HomeButtonPanel.setBackground(new Color(64, 43, 100));
        Cursor cursor = new Cursor(Cursor.DEFAULT_CURSOR);
        setCursor(cursor);
        grafik();
    }//GEN-LAST:event_HomeButtonLabelMouseExited

    private void ScannedButtonLabelMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_ScannedButtonLabelMouseExited
        ScannedButtonPanel.setBackground(new Color(64, 43, 100));
        Cursor cursor = new Cursor(Cursor.DEFAULT_CURSOR);
        setCursor(cursor);
        grafik();
    }//GEN-LAST:event_ScannedButtonLabelMouseExited

    private void AboutButtonLabelMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_AboutButtonLabelMouseExited
        AboutButtonPanel.setBackground(new Color(54, 33, 89));
        Cursor cursor = new Cursor(Cursor.DEFAULT_CURSOR);
        setCursor(cursor);
        grafik();
    }//GEN-LAST:event_AboutButtonLabelMouseExited

    private void HomeClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_HomeClicked
        HomeButtonPanel.setBackground(Color.getHSBColor(85, 65, 118));
        HomeButtonPanel.setBackground(Color.getHSBColor(85, 65, 118));
        pageNumber = 0;
        grafik();
    }//GEN-LAST:event_HomeClicked

    private void ScanButtonLabelMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_ScanButtonLabelMouseClicked
        ScanButtonPanel.setBackground(Color.getHSBColor(85, 65, 118));
        ScanButtonPanel.setBackground(Color.getHSBColor(85, 65, 118));
        pageNumber = 1;
        grafik();
    }//GEN-LAST:event_ScanButtonLabelMouseClicked

    private void ScannedButtonLabelMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_ScannedButtonLabelMouseClicked
        ScannedButtonPanel.setBackground(Color.getHSBColor(85, 65, 118));
        ScannedButtonPanel.setBackground(Color.getHSBColor(85, 65, 118));
        pageNumber = 2;
        grafik();
    }//GEN-LAST:event_ScannedButtonLabelMouseClicked

    private void AboutButtonLabelMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_AboutButtonLabelMouseClicked
        AboutButtonPanel.setBackground(new Color(85, 65, 118));
        AboutButtonPanel.setBackground(Color.getHSBColor(85, 65, 118));
        pageNumber = 3;
        grafik();
    }//GEN-LAST:event_AboutButtonLabelMouseClicked

    private void ScanBuutonMousePressed(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_ScanBuutonMousePressed
        HomePanel.setVisible(false);
        ScanPanel.setVisible(true);
        StatusIcon.setVisible(false);
        ScannedPanel.setVisible(false);
        AboutPanel.setVisible(false);
        Stable.setVisible(true);
        ApiKeyStatus.setVisible(false);
        sizeController = 1;
        ResultPanel.setVisible(false);
        ResultPanelStable.setVisible(false);
        ScannedFilesStable.setVisible(false);
        SettingsPanel.setVisible(false);
        fileName.setText("There is no file selected!");
        filePath.setText("");
        FileSize.setText("");
        fileExtension.setText("");
        FileName.setVisible(false);
        files.clear();
        ResultPanel6.removeAll();
        jLabel6.setText(ScanButtonLabel.getText().toUpperCase());
        pageNumber = 1;
        grafik();
    }//GEN-LAST:event_ScanBuutonMousePressed

    private void HomeEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_HomeEntered
        grafik();
        HomeButtonPanel.setBackground(new Color(85, 65, 118));
        Cursor cursor = new Cursor(Cursor.HAND_CURSOR);
        setCursor(cursor);
    }//GEN-LAST:event_HomeEntered

    private void CloseLabelMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_CloseLabelMouseEntered
        ClosePanel.setBackground(new Color(255, 96, 92));
    }//GEN-LAST:event_CloseLabelMouseEntered

    private void CloseLabelMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_CloseLabelMouseExited
        ClosePanel.setBackground(new Color(255, 255, 255));
    }//GEN-LAST:event_CloseLabelMouseExited

    private void minimiseMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_minimiseMouseEntered
        MinimisePanel.setBackground(new Color(240, 240, 240));
    }//GEN-LAST:event_minimiseMouseEntered

    private void minimiseMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_minimiseMouseExited
        MinimisePanel.setBackground(new Color(255, 255, 255));
    }//GEN-LAST:event_minimiseMouseExited

    private void minimiseMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_minimiseMouseClicked
        setState(JFrame.ICONIFIED);
    }//GEN-LAST:event_minimiseMouseClicked

    private void AboutButtonLabelMousePressed(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_AboutButtonLabelMousePressed
        HomePanel.setVisible(false);
        ScanPanel.setVisible(false);
        ScannedPanel.setVisible(false);
        ResultPanel.setVisible(false);
        SettingsPanel.setVisible(false);
        Stable.setVisible(false);
        ResultPanelStable.setVisible(false);
        ScannedFilesStable.setVisible(false);
        StatusIcon.setVisible(false);
        ApiKeyStatus.setVisible(false);
        AboutPanel.setVisible(true);
        jLabel6.setText(AboutButtonLabel.getText().toUpperCase());
        sizeController = 1;
        pageNumber = 3;
        grafik();
    }//GEN-LAST:event_AboutButtonLabelMousePressed

    private void CloseLabelMousePressed(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_CloseLabelMousePressed
        ClosePanel.setBackground(new Color(192, 0, 0));
        System.exit(0);
        grafik();
    }//GEN-LAST:event_CloseLabelMousePressed

    private void ScannedButtonLabelMousePressed(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_ScannedButtonLabelMousePressed
        TotalAll.setText(String.valueOf(this.detectifyDB.getTotalCount()));
        TotalFiles.setText(String.valueOf(this.detectifyDB.getFileCount()));
        TotalURLs.setText(String.valueOf(this.detectifyDB.getURLCount()));
        StatusIcon.setVisible(false);
        HomePanel.setVisible(false);
        ScanPanel.setVisible(false);
        ScannedPanel.setVisible(true);
        ApiKeyStatus.setVisible(false);
        sizeController = 1;
        AboutPanel.setVisible(false);
        ResultPanel.setVisible(false);
        SettingsPanel.setVisible(false);
        ScannedFilesStable.setVisible(true);
        Stable.setVisible(false);
        ResultPanelStable.setVisible(false);
        jLabel6.setText(ScannedButtonLabel.getText().toUpperCase().replace('İ', 'I'));
        this.getScannedFiles();
        ResultPanel6.removeAll();
        pageNumber = 2;
        grafik();
    }//GEN-LAST:event_ScannedButtonLabelMousePressed

    private void HomeButtonLabelMouseDragged(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_HomeButtonLabelMouseDragged
    }//GEN-LAST:event_HomeButtonLabelMouseDragged

    private void HomeButtonLabelMousePressed(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_HomeButtonLabelMousePressed
        HomePanel.setVisible(true);
        StatusIcon.setVisible(false);
        ScanPanel.setVisible(false);
        ScannedPanel.setVisible(false);
        AboutPanel.setVisible(false);
        SettingsPanel.setVisible(false);
        ApiKeyStatus.setVisible(false);
        sizeController = 1;
        ResultPanel.setVisible(false);
        ScannedFilesStable.setVisible(false);
        jLabel6.setText("HOME");
        jLabel6.setText(HomeButtonLabel.getText().toUpperCase());
        pageNumber = 0;
        grafik();
    }//GEN-LAST:event_HomeButtonLabelMousePressed

    private void SelectedFlagMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_SelectedFlagMouseEntered
        Language.setBackground(new Color(85, 65, 118));
    }//GEN-LAST:event_SelectedFlagMouseEntered

    private void SelectedFlagMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_SelectedFlagMouseExited
        Language.setBackground(new Color(54, 33, 89));
    }//GEN-LAST:event_SelectedFlagMouseExited

    private void jLabel5MouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jLabel5MouseEntered
        Language.setBackground(new Color(85, 65, 118));
        Cursor cursor = new Cursor(Cursor.HAND_CURSOR);
        setCursor(cursor);
    }//GEN-LAST:event_jLabel5MouseEntered

    private void jLabel5MouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jLabel5MouseExited
        Language.setBackground(new Color(54, 33, 89));
        Cursor cursor = new Cursor(Cursor.DEFAULT_CURSOR);
        setCursor(cursor);
    }//GEN-LAST:event_jLabel5MouseExited
    private void jLabel5MousePressed(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jLabel5MousePressed
        if (counter5 == 0) {
            Languages.setVisible(true);
            counter5 = 1;
        } else if (counter5 == 1) {
            Languages.setVisible(false);
            counter5 = 0;
        }
    }//GEN-LAST:event_jLabel5MousePressed

    private void jLabel4MouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jLabel4MouseEntered
        FirstFlag.setBackground(new Color(85, 65, 118));
        Cursor cursor = new Cursor(Cursor.HAND_CURSOR);
        setCursor(cursor);
    }//GEN-LAST:event_jLabel4MouseEntered

    private void jLabel4MouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jLabel4MouseExited
        FirstFlag.setBackground(new Color(54, 33, 89));
        Cursor cursor = new Cursor(Cursor.DEFAULT_CURSOR);
        setCursor(cursor);
    }//GEN-LAST:event_jLabel4MouseExited
    static int counter6 = 0;
    private void jLabel4MousePressed(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jLabel4MousePressed
        Icon icon = SelectedFlag.getIcon();
        Icon icon2 = jLabel4.getIcon();
        SelectedFlag.setIcon(icon2);
        jLabel4.setIcon(icon);
        Languages.setVisible(false);
        counter5 = 0;
        if (counter6 == 0) {
            changeTurkish();
            counter6 = 1;
        } else if (counter6 == 1) {
            changeEnglish();
            counter6 = 0;
        }
    }//GEN-LAST:event_jLabel4MousePressed

    private void ScanMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_ScanMouseEntered
        if (sizeController == 1) {
            //create custom cursor
            Toolkit toolKit = Toolkit.getDefaultToolkit();
            Image img = toolKit.getImage(getClass().getResource("/Images/aero_unavail.png"));
            Point point = new Point(0, 0);

            Cursor cursor = toolKit.createCustomCursor(img, point, "Cursor");
            setCursor(cursor);
        } else {
            ScanButton.setBackground(new Color(85, 65, 118));
            Cursor cursor = new Cursor(Cursor.HAND_CURSOR);
            setCursor(cursor);
        }


    }//GEN-LAST:event_ScanMouseEntered

    private void ScanMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_ScanMouseExited
        ScanButton.setBackground(new Color(54, 33, 89));
        Cursor cursor = new Cursor(Cursor.DEFAULT_CURSOR);
        setCursor(cursor);
    }//GEN-LAST:event_ScanMouseExited

    private void jButton1MouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jButton1MouseEntered
        Cursor cursor = new Cursor(Cursor.HAND_CURSOR);
        setCursor(cursor);    }//GEN-LAST:event_jButton1MouseEntered

    private void jButton1MouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jButton1MouseExited
        Cursor cursor = new Cursor(Cursor.DEFAULT_CURSOR);
        setCursor(cursor);    }//GEN-LAST:event_jButton1MouseExited
    static int fileController = 1;
    static int sizeController = 1;
    private void jButton1MousePressed(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jButton1MousePressed
        FileOperations operator = new FileOperations();
        File[] selectedFiles = operator.getFile();
        try {
            File file = selectedFiles[0];
            if (files.size() > 0) {
                files.clear();
                files.add(file);
                FileName.setVisible(true);
                jLabel32.setText(file.getName().length() > 15 ? file.getName().substring(0, 15) + "..." : file.getName());
                fileName.setText(file.getName().length() > 35 ? file.getName().substring(0, 35) + "..." : file.getName());
                fileName2 = file.getPath();
                filePath.setText(file.getPath().length() > 42 ? file.getPath().substring(0, 42) + "..." : file.getPath());
                if (file.length() < 1024 * 1024) {
                    FileSize.setText(String.valueOf((float) file.length() / (float) 1024).substring(0, 3) + "KB");
                } else {
                    FileSize.setText(String.valueOf((float) file.length() / (float) 1024 / (float) 1024).substring(0, 4) + "MB");
                }
                fileExtension.setText((file.getName().substring(file.getName().lastIndexOf("."), file.getName().length())));
                if (file.length() > 33554432) {
                    sizeController = 1;
                    StatusIcon.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/icons8-error-15.png")));
                    StatusIcon.setVisible(true);
                } else {
                    sizeController = 0;
                    StatusIcon.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/icons8-checkmark-15.png")));
                    StatusIcon.setVisible(true);

                }
            } else {
                files.add(file);
                FileName.setVisible(true);
                jLabel32.setText(file.getName().length() > 15 ? file.getName().substring(0, 15) + "..." : file.getName());
                fileName.setText(file.getName().length() > 35 ? file.getName().substring(0, 35) + "..." : file.getName());
                fileName2 = file.getPath();
                filePath.setText(file.getPath().length() > 42 ? file.getPath().substring(0, 42) + "..." : file.getPath());
                //choose file
                if (file.length() < 1024 * 1024) {
                    FileSize.setText(String.valueOf((float) file.length() / (float) 1024).substring(0, 3) + "KB");
                } else {
                    FileSize.setText(String.valueOf((float) file.length() / (float) 1024 / (float) 1024).substring(0, 4) + "MB");
                }
                fileExtension.setText((file.getName().substring(file.getName().lastIndexOf("."), file.getName().length())));
                if (file.length() > 33554432) {

                    sizeController = 1;
                    StatusIcon.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/icons8-error-15.png")));
                    StatusIcon.setVisible(true);
                } else {
                    sizeController = 0;
                    StatusIcon.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/icons8-checkmark-15.png")));
                    StatusIcon.setVisible(true);

                }
            }
        } catch (ArrayIndexOutOfBoundsException e) {

        }
    }//GEN-LAST:event_jButton1MousePressed

    private void FILEMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_FILEMouseEntered
        if (fileController == 0) {
            jLabel29.setVisible(true);
        }
        Cursor cursor = new Cursor(Cursor.HAND_CURSOR);
        setCursor(cursor);
    }//GEN-LAST:event_FILEMouseEntered

    private void FILEMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_FILEMouseExited
        if (fileController == 0) {
            jLabel29.setVisible(false);
        }
        Cursor cursor = new Cursor(Cursor.DEFAULT_CURSOR);
        setCursor(cursor);
    }//GEN-LAST:event_FILEMouseExited

    private void jLabel34MouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jLabel34MouseEntered
        Cursor cursor = new Cursor(Cursor.HAND_CURSOR);
        setCursor(cursor);
    }//GEN-LAST:event_jLabel34MouseEntered

    private void jLabel34MouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jLabel34MouseExited
        Cursor cursor = new Cursor(Cursor.DEFAULT_CURSOR);
        setCursor(cursor);
    }//GEN-LAST:event_jLabel34MouseExited

    private void jLabel34MousePressed(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jLabel34MousePressed
        files.clear();
        sizeController = 1;
        StatusIcon.setVisible(false);
        FileName.setVisible(false);
        fileName.setText("There is no selected file!");
        filePath.setText("");
        FileSize.setText("");
        fileExtension.setText("");
    }//GEN-LAST:event_jLabel34MousePressed

    private void ScanMousePressed(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_ScanMousePressed
        if (sizeController == 0) {
            Cursor cursor = new Cursor(Cursor.WAIT_CURSOR);
            setCursor(cursor);
            if (files.isEmpty()) {

            } else {
                String searchFile = files.get(0).getPath();
                try {
                    FileOperations operator = new FileOperations();
                    String hash = operator.toSHA256(searchFile);
                    hashScan(searchFile, hash);
                } catch (NoSuchAlgorithmException ex) {
                    Logger.getLogger(GUI.class.getName()).log(Level.SEVERE, null, ex);
                } catch (IOException ex) {
                    Logger.getLogger(GUI.class.getName()).log(Level.SEVERE, null, ex);
                } catch (AWTException ex) {
                    Logger.getLogger(GUI.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        } else {

        }


    }//GEN-LAST:event_ScanMousePressed
    int ctrl = 0;
    private void URLMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_URLMouseEntered
        if (ctrl == 0) {
            jLabel31.setVisible(true);
        }
        Cursor cursor = new Cursor(Cursor.HAND_CURSOR);
        setCursor(cursor);
    }//GEN-LAST:event_URLMouseEntered

    private void URLMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_URLMouseExited
        if (ctrl == 0) {
            jLabel31.setVisible(false);
        }
        Cursor cursor = new Cursor(Cursor.DEFAULT_CURSOR);
        setCursor(cursor);
    }//GEN-LAST:event_URLMouseExited

    private void URLMousePressed(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_URLMousePressed
        files.clear();
        sizeController = 1;
        StatusIcon.setVisible(false);
        FileNameLabel.setText("");
        ExtensionLabel.setText("");
        SizeLabel.setText("");
        FileNameLabel.setText("");
        jLabel31.setVisible(true);
        FilePanel.setVisible(false);
        URLPanel.setVisible(true);
        ctrl++;
        jLabel29.setVisible(false);
        fileController = 0;
        ResultPanel6.removeAll();
        FileName.setVisible(false);
        fileName.setText("There is no file!");
        filePath.setText("");
        FileSize.setText("");
        fileExtension.setText("");
        ResultPanelStable.setVisible(false);
    }//GEN-LAST:event_URLMousePressed

    private void FILEMousePressed(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_FILEMousePressed
        FilePanel.setVisible(true);
        URLPanel.setVisible(false);
        jLabel29.setVisible(true);
        jLabel31.setVisible(false);
        ctrl = 0;
        fileController = 1;
    }//GEN-LAST:event_FILEMousePressed

    private void URLTfMousePressed(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_URLTfMousePressed
        URLTf.setText("");
        URLTf.setForeground(new java.awt.Color(0, 0, 0));
    }//GEN-LAST:event_URLTfMousePressed

    private void SearchButtonMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_SearchButtonMouseEntered
        Cursor cursor = new Cursor(Cursor.HAND_CURSOR);
        setCursor(cursor);
    }//GEN-LAST:event_SearchButtonMouseEntered

    private void SearchButtonMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_SearchButtonMouseExited
        Cursor cursor = new Cursor(Cursor.DEFAULT_CURSOR);
        setCursor(cursor);
    }//GEN-LAST:event_SearchButtonMouseExited

    private void ScanButtonMousePressed(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_ScanButtonMousePressed
        // TODO add your handling code here:
    }//GEN-LAST:event_ScanButtonMousePressed

    private void SeeResultActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_SeeResultActionPerformed
        jScrollPane1.setVisible(true);
        QuestionFrame.setVisible(false);

        HomePanel.setVisible(false);
        ScanPanel.setVisible(false);
        ScannedPanel.setVisible(false);
        AboutPanel.setVisible(false);
        ResultPanel.setVisible(true);
        Stable.setVisible(false);
        ResultPanelStable.setVisible(true);
    }//GEN-LAST:event_SeeResultActionPerformed

    private void QuestionFrameMousePressed(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_QuestionFrameMousePressed
        // TODO add your handling code here:
    }//GEN-LAST:event_QuestionFrameMousePressed

    private void ScanAgainActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_ScanAgainActionPerformed
        Cursor cursor = new Cursor(Cursor.WAIT_CURSOR);
        setCursor(cursor);
        String fileName2 = files.get(0).getPath();
        QuestionFrame.setVisible(false);
        try {
            uploadGiven(fileName2, false);
        } catch (AWTException ex) {
            Logger.getLogger(GUI.class.getName()).log(Level.SEVERE, null, ex);
        }

    }//GEN-LAST:event_ScanAgainActionPerformed

    private void URLTfActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_URLTfActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_URLTfActionPerformed
    static int con = 1;
    private void SettingsButtonLabelMousePressed(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_SettingsButtonLabelMousePressed
        HomePanel.setVisible(false);
        ScanPanel.setVisible(false);
        AboutPanel.setVisible(false);
        ResultPanel.setVisible(false);
        Stable.setVisible(false);
        ResultPanelStable.setVisible(false);
        ScannedFilesStable.setVisible(false);
        ScannedPanel.setVisible(false);
        StatusIcon.setVisible(false);
        ApiKeyStatus.setVisible(false);
        SettingsPanel.setVisible(true);
        sizeController = 1;
        jLabel6.setText(HomeButtonLabel.getText().toUpperCase());
        pageNumber = 4;
        if (con == 1) {
            jLabel6.setText("SETTINGS");
        } else {
            jLabel6.setText("AYARLAR");
        }
        grafik();
    }//GEN-LAST:event_SettingsButtonLabelMousePressed

    private void SettingsButtonLabelMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_SettingsButtonLabelMouseClicked
        pageNumber = 4;
        grafik();
    }//GEN-LAST:event_SettingsButtonLabelMouseClicked

    private void SettingsButtonLabelMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_SettingsButtonLabelMouseEntered
        grafik();
        SettingsButtonPanel.setBackground(new Color(85, 65, 118));
        Cursor cursor = new Cursor(Cursor.HAND_CURSOR);
        setCursor(cursor);
    }//GEN-LAST:event_SettingsButtonLabelMouseEntered

    private void SettingsButtonLabelMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_SettingsButtonLabelMouseExited
        HomeButtonPanel.setBackground(new Color(64, 43, 100));
        Cursor cursor = new Cursor(Cursor.DEFAULT_CURSOR);
        setCursor(cursor);
        grafik();
    }//GEN-LAST:event_SettingsButtonLabelMouseExited

    private void SaveButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_SaveButtonActionPerformed

        this.updateAPIKey();
        //if api key is correct!
        ApiKeyStatus.setText("API Key has been changed successfully!");
        ApiKeyStatus.setVisible(true);
        //else 
        //ApiKeyStatus.setText("Invalid API Key!");

    }//GEN-LAST:event_SaveButtonActionPerformed

    private void jTable1MouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jTable1MouseClicked
        // TODO add your handling code here:
        if (jTable1.getSelectedColumn() == 5) {
            ResultPanel6.removeAll();
            this.detectifyDB.delete(jTable1.getValueAt(jTable1.getSelectedRow(), 0).toString());
            this.getScannedFiles();
            TotalAll.setText(String.valueOf(this.detectifyDB.getTotalCount()));
            TotalFiles.setText(String.valueOf(this.detectifyDB.getFileCount()));
            TotalURLs.setText(String.valueOf(this.detectifyDB.getURLCount()));
        } else if (jTable1.getSelectedColumn() == 6) {
            String scan_id = jTable1.getValueAt(jTable1.getSelectedRow(), 3).toString();
            try {
                Cursor cursor = new Cursor(Cursor.WAIT_CURSOR);
                setCursor(cursor);
                if (jTable1.getValueAt(jTable1.getSelectedRow(), 2).toString().equals("url")) {
                    urlScan(scan_id, false);
                } else {
                    scanCheckerFile(scan_id);
                }
                Cursor dcursor = new Cursor(Cursor.DEFAULT_CURSOR);
                setCursor(dcursor);
            } catch (AWTException ex) {
                Logger.getLogger(GUI.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }//GEN-LAST:event_jTable1MouseClicked
    private void CustomTitleBarMouseDragged(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_CustomTitleBarMouseDragged
        this.setLocation(evt.getXOnScreen() - (this.x - this.leftCord), evt.getYOnScreen());
    }//GEN-LAST:event_CustomTitleBarMouseDragged

    private void CustomTitleBarMousePressed(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_CustomTitleBarMousePressed
        // TODO add your handling code here:
        this.x = evt.getXOnScreen();
        this.y = evt.getYOnScreen();
        this.leftCord = this.getLocation().x;
    }//GEN-LAST:event_CustomTitleBarMousePressed

    private void SearchButtonMousePressed(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_SearchButtonMousePressed
        Cursor cursor = new Cursor(Cursor.WAIT_CURSOR);
        setCursor(cursor);
        String url = URLTf.getText();
        try {
            urlScan(url, true);
            QuestionFrame.setVisible(false);
        } catch (AWTException ex) {
            Logger.getLogger(GUI.class.getName()).log(Level.SEVERE, null, ex);
        }

    }//GEN-LAST:event_SearchButtonMousePressed

    private void jLabel35MouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jLabel35MouseEntered
        Cursor cursor = new Cursor(Cursor.HAND_CURSOR);
        setCursor(cursor);
    }//GEN-LAST:event_jLabel35MouseEntered

    private void jLabel35MouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jLabel35MouseExited
        Cursor cursor = new Cursor(Cursor.DEFAULT_CURSOR);
        setCursor(cursor);
    }//GEN-LAST:event_jLabel35MouseExited

    private void jLabel35MousePressed(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jLabel35MousePressed
        try {
            try {
                Desktop.getDesktop().browse(new URL("https://github.com/canumay/detectify-new").toURI());
            } catch (IOException ex) {
                Logger.getLogger(GUI.class.getName()).log(Level.SEVERE, null, ex);
            }
        } catch (URISyntaxException ex) {
            Logger.getLogger(GUI.class.getName()).log(Level.SEVERE, null, ex);
        }


    }//GEN-LAST:event_jLabel35MousePressed

    private void jLabel36MousePressed(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jLabel36MousePressed
        try {
            try {
                Desktop.getDesktop().browse(new URL(this.currentReportURL.replace("\"", "")).toURI());
            } catch (IOException ex) {
                Logger.getLogger(GUI.class.getName()).log(Level.SEVERE, null, ex);
            }
        } catch (URISyntaxException ex) {
            Logger.getLogger(GUI.class.getName()).log(Level.SEVERE, null, ex);
        }
    }//GEN-LAST:event_jLabel36MousePressed

    private void jLabel36MouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jLabel36MouseExited
        jLabel36.setForeground(new Color(0, 0, 0));
        Cursor cursor = new Cursor(Cursor.DEFAULT_CURSOR);
        setCursor(cursor);
    }//GEN-LAST:event_jLabel36MouseExited

    private void jLabel36MouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jLabel36MouseEntered
        jLabel36.setForeground(new Color(0, 0, 255));
        Cursor cursor = new Cursor(Cursor.HAND_CURSOR);
        setCursor(cursor);
    }//GEN-LAST:event_jLabel36MouseEntered
    static int i = 0;

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;

                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(GUI.class
                    .getName()).log(java.util.logging.Level.SEVERE, null, ex);

        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(GUI.class
                    .getName()).log(java.util.logging.Level.SEVERE, null, ex);

        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(GUI.class
                    .getName()).log(java.util.logging.Level.SEVERE, null, ex);

        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(GUI.class
                    .getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            @Override
            public void run() {
                new GUI().setVisible(true);
            }
        });
    }
    /*
public static void drawGamePanel(){
    //Create game panel and attributes
    jPanel gamePanel = new jPanel();
    Image background = Toolkit.getDefaultToolkit().createImage("Background.png");
    gamePanel.drawImage(background, 0, 0, null);
    //Set Return
    
}
,*/
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JLabel AboutButtonLabel;
    private javax.swing.JPanel AboutButtonPanel;
    private javax.swing.JPanel AboutPanel;
    private javax.swing.JPanel AllTotal;
    private javax.swing.JLabel ApiKeyStatus;
    private javax.swing.JLabel CloseLabel;
    private javax.swing.JPanel ClosePanel;
    private javax.swing.JPanel ContentPanel;
    private javax.swing.JPanel CustomTitleBar;
    private javax.swing.JScrollPane DatabaseData;
    private javax.swing.JLabel DragAndDrop;
    private javax.swing.JLabel ExtensionLabel;
    private javax.swing.JLabel FExtensionLabel;
    private javax.swing.JPanel FILE;
    private javax.swing.JLabel FSizeLabel;
    private javax.swing.JPanel FileName;
    private javax.swing.JLabel FileNameLabel;
    private javax.swing.JPanel FilePanel;
    private javax.swing.JLabel FileSize;
    private javax.swing.JLabel FileTypeLabel;
    private javax.swing.JPanel FilesTotal;
    private javax.swing.JPanel FirstFlag;
    private javax.swing.JPanel GeneralPanel;
    private javax.swing.JLabel HashLabel;
    private javax.swing.JLabel HomeButtonLabel;
    private javax.swing.JPanel HomeButtonPanel;
    private javax.swing.JPanel HomePanel;
    private javax.swing.JPanel Language;
    private javax.swing.JPanel Languages;
    private javax.swing.JLabel Logo;
    private javax.swing.JPanel MainPanel;
    private javax.swing.JPanel MenuPanel;
    private javax.swing.JPanel MinimisePanel;
    private javax.swing.JLabel NameLabel;
    private javax.swing.JLabel OS;
    private javax.swing.JPanel Pannels;
    private javax.swing.JLabel PathLabel;
    private javax.swing.JFrame QuestionFrame;
    private javax.swing.JPanel ResultPanel;
    private javax.swing.JPanel ResultPanel6;
    private javax.swing.JPanel ResultPanelStable;
    private javax.swing.JButton SaveButton;
    private javax.swing.JLabel Scan;
    private javax.swing.JButton ScanAgain;
    private javax.swing.JPanel ScanButton;
    private javax.swing.JLabel ScanButtonLabel;
    private javax.swing.JPanel ScanButtonPanel;
    private javax.swing.JPanel ScanChooseBoxes;
    private javax.swing.JPanel ScanContent;
    private javax.swing.JPanel ScanPanel;
    private javax.swing.JLabel ScannedButtonLabel;
    private javax.swing.JPanel ScannedButtonPanel;
    private javax.swing.JPanel ScannedFilesInfoBoxes;
    private javax.swing.JPanel ScannedFilesStable;
    private javax.swing.JPanel ScannedPanel;
    private javax.swing.JLabel SearchButton;
    private javax.swing.JButton SeeResult;
    private javax.swing.JLabel SelectedFlag;
    private javax.swing.JPanel SettingContent;
    private javax.swing.JLabel SettingsButtonLabel;
    private javax.swing.JPanel SettingsButtonPanel;
    private javax.swing.JPanel SettingsPanel;
    private javax.swing.JLabel SizeLabel;
    private javax.swing.JPanel Stable;
    private javax.swing.JPanel StableBig;
    private javax.swing.JLabel Status;
    private javax.swing.JLabel StatusIcon;
    private javax.swing.JLabel StatusLabel;
    private javax.swing.JPanel StatusPanel;
    private javax.swing.JPanel SystemInformation;
    private javax.swing.JLabel Text;
    private javax.swing.JLabel Text2;
    private javax.swing.JLabel TotalAll;
    private javax.swing.JLabel TotalCount;
    private javax.swing.JLabel TotalFiles;
    private javax.swing.JLabel TotalURLs;
    private javax.swing.JPanel URL;
    private javax.swing.JPanel URLPanel;
    private javax.swing.JTextField URLTf;
    private javax.swing.JPanel URLTotal;
    private javax.swing.JLabel WWWLogo;
    private javax.swing.JTextField apiKeyText;
    private javax.swing.JLabel fileExtension;
    private javax.swing.JLabel fileName;
    private javax.swing.JLabel filePath;
    private javax.swing.JButton jButton1;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel10;
    private javax.swing.JLabel jLabel11;
    private javax.swing.JLabel jLabel12;
    private javax.swing.JLabel jLabel13;
    private javax.swing.JLabel jLabel14;
    private javax.swing.JLabel jLabel15;
    private javax.swing.JLabel jLabel16;
    private javax.swing.JLabel jLabel17;
    private javax.swing.JLabel jLabel18;
    private javax.swing.JLabel jLabel19;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel21;
    private javax.swing.JLabel jLabel22;
    private javax.swing.JLabel jLabel24;
    private javax.swing.JLabel jLabel25;
    private javax.swing.JLabel jLabel26;
    private javax.swing.JLabel jLabel27;
    private javax.swing.JLabel jLabel28;
    private javax.swing.JLabel jLabel29;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel30;
    private javax.swing.JLabel jLabel31;
    private javax.swing.JLabel jLabel32;
    private javax.swing.JLabel jLabel33;
    private javax.swing.JLabel jLabel34;
    private javax.swing.JLabel jLabel35;
    private javax.swing.JLabel jLabel36;
    private javax.swing.JLabel jLabel37;
    private javax.swing.JLabel jLabel38;
    private javax.swing.JLabel jLabel39;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel40;
    private javax.swing.JLabel jLabel41;
    private javax.swing.JLabel jLabel42;
    private javax.swing.JLabel jLabel43;
    private javax.swing.JLabel jLabel44;
    private javax.swing.JLabel jLabel45;
    private javax.swing.JLabel jLabel46;
    private javax.swing.JLabel jLabel48;
    private javax.swing.JLabel jLabel49;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel50;
    private javax.swing.JLabel jLabel52;
    private javax.swing.JLabel jLabel53;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JLabel jLabel8;
    private javax.swing.JLabel jLabel9;
    private javax.swing.JPanel jPanel11;
    private javax.swing.JPanel jPanel12;
    private javax.swing.JPanel jPanel13;
    private javax.swing.JPanel jPanel15;
    private javax.swing.JPanel jPanel18;
    private javax.swing.JPanel jPanel22;
    private javax.swing.JPanel jPanel24;
    private javax.swing.JPanel jPanel3;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JTable jTable1;
    private javax.swing.JLabel minimise;
    // End of variables declaration//GEN-END:variables
}
