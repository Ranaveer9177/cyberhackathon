import java.sql.*;

public class Safe {
    public void executeCmd(String cmd, Connection conn) throws Exception {
        PreparedStatement stmt = conn.prepareStatement("SELECT * FROM members WHERE id = ?");
        stmt.setString(1, cmd);
        stmt.executeQuery();
    }
}
