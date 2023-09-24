package main

import (
	"fmt"
	"html/template"
	"net/http"
)

var users = map[string]string{
	"admin": "adminpass",
	"alice": "alicepass",
	"bob":   "bobpass",
}

func main() {
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/welcome", welcomeHandler)
	http.ListenAndServe(":8080", nil)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Welcome to the web app!<br>")
	fmt.Fprint(w, `<a href="/login">Login</a>`)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		// Authenticate user
		if storedPassword, ok := users[username]; ok && storedPassword == password {
			fmt.Fprintf(w, "Welcome, %s!<br>", username)
			fmt.Fprint(w, "Logout: <a href='/'>Logout</a>")
		} else {
			fmt.Fprint(w, "Invalid login. <a href='/login'>Try again</a>")
		}
	} else {
		loginTemplate.Execute(w, nil)
	}
}

func welcomeHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Welcome to the web app!")
}

var loginTemplate = template.Must(template.New("").Parse(`
<!DOCTYPE html>
<html>
<head>
	<title>Login</title>
</head>
<body>
	<h1>Login</h1>
	<form method="post">
		<label for="username">Username:</label>
		<input type="text" name="username"><br>
		<label for="password">Password:</label>
		<input type="password" name="password"><br>
		<input type="submit" value="Login">
	</form>
</body>
</html>
`))
