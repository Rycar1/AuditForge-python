func search(c *gin.Context, db *sql.DB) {
  q := c.Query("q")
  db.Query("SELECT * FROM products WHERE name = '" + q + "'")
}

func main() {
  router := gin.Default()
  router.GET("/search", search)
}
