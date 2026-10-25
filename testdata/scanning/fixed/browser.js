// Fixed control: insert untrusted content as text.
const searchTerm = new URLSearchParams(window.location.search).get("term");
document.querySelector("#search-results").textContent = searchTerm;
