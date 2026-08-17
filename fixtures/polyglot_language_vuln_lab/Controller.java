@RestController
class Controller {
  @GetMapping("/search")
  public String search(@RequestParam String q, Statement statement) throws Exception {
    return statement.executeQuery("SELECT * FROM products WHERE name = '" + q + "'").toString();
  }
}
