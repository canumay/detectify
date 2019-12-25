
import java.awt.AWTException;
import java.awt.Image;
import java.awt.SystemTray;
import java.awt.Toolkit;
import java.awt.TrayIcon;
import java.awt.TrayIcon.MessageType;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
/**
 *
 * @author Can Umay
 */
public class Notify {

    public static void displayTray(String message, String messageType) throws AWTException {
        SystemTray tray = SystemTray.getSystemTray();
        Image image = Toolkit.getDefaultToolkit().createImage("icon.png");
        TrayIcon trayIcon = new TrayIcon(image, "Detectify");
        trayIcon.setImageAutoSize(true);
        tray.add(trayIcon);
        switch (messageType) {
            case "error":
                trayIcon.displayMessage("Detectify", message, MessageType.ERROR);
                break;
            case "warning":
                trayIcon.displayMessage("Detectify", message, MessageType.WARNING);
                break;
            case "info":
                trayIcon.displayMessage("Detectify", message, MessageType.INFO);
                break;
        }
    }
}
