// Deliberately vulnerable regression fixture; never serve this file.
const searchTerm = new URLSearchParams(window.location.search).get("term");
document.querySelector("#search-results").innerHTML = searchTerm;
