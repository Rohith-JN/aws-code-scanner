// Deliberately vulnerable regression fixture; never deploy this application.
const express = require("express");
const app = express();

app.get("/search", (request, response) => {
  const searchTerm = request.query.term;
  response.send(`<section>Search: ${searchTerm}</section>`);
});

app.listen(3000);
