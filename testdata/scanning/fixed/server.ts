// Fixed control: the same HTTP input is encoded before HTML insertion.
const express = require("express");
const escapeHtml = require("escape-html");
const app = express();

app.get("/search", (request, response) => {
  const searchTerm = request.query.term;
  response.send(`<section>Search: ${escapeHtml(searchTerm)}</section>`);
});

app.listen(3001);
