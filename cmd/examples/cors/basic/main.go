package main

import (
	"flag"
	"log"
	"net/http"
)

//public cors

// create a simple HTML page with some JS added. Obviously in a professional
// setting, we would have the JS code in a script file
const html = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
</head>

<body>
    <h1>Appletree CORS</h1>
    <div id="output"></div>
    <script>
         document.addEventListener('DOMContentLoaded', function() {
         fetch("http://localhost:3000/api/v1/books")
         .then(function (response) {
                         response.text().then(function (text) {
                         document.getElementById("output").innerHTML = text;
                    });
                },
function(err) {
                    document.getElementById("output").innerHTML = err;
                }
            );
        });
  </script>
</body>
</html>`

func main() {
	addr := flag.String("addr", ":9005", "Server address")
	flag.Parse()

	log.Printf("starting server on %s", *addr)
	err := http.ListenAndServe(*addr,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(html))
		}))
	log.Fatal(err)
}
