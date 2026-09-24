import java.sql.*;

public class Vulnerable {
    public void executeCmd(String cmd, Connection conn) throws Exception {
        Runtime.getRuntime().exec(cmd);

        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM members WHERE id = '" + cmd + "'");
    }
}
