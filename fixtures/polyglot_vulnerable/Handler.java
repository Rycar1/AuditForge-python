import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

class Handler {
  public String user(HttpServletRequest req, Statement statement) throws Exception {
    String id = req.getParameter("id");
    return statement.executeQuery("select * from users where id = " + id).toString();
  }
}
