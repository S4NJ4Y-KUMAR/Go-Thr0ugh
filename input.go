package main

import (
	"fmt"
	"html/template"
	"net/http"
)

var users = map[string]string{
	"Sanjay": "Sanjaypass",
	"Jei":    "Jeipass",
	"Sugash": "Sugashpass",
}

func main() {
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/welcome", welcomeHandler)
	http.ListenAndServe(":8080", nil)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Welcome to the vulnerable web app!<br>")
	fmt.Fprint(w, `<a href="/login">Login</a>`)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		// Simulate SQL Injection (Vulnerable Code)
		query := fmt.Sprintf("SELECT * FROM users WHERE username='%s' AND password='%s'", username, password)
		fmt.Println("Executing SQL Query:", query)

		// Authenticate user
		if storedPassword, ok := users[username]; ok && storedPassword == password {
			fmt.Fprintf(w, "Welcome, %s!<br>", username)

			// Simulate XSS (Vulnerable Code)
			fmt.Fprintf(w, "Your password is: %s<br>", password)
			fmt.Fprint(w, "Logout: <a href='/'>Logout</a>")
		} else {
			fmt.Fprint(w, "Invalid login. <a href='/login'>Try again</a>")
		}
	} else {
		loginTemplate.Execute(w, nil)
	}
}

func welcomeHandler(w http.ResponseWriter, r *http.Request) {
	// Simulate CSRF (Vulnerable Code)
	if r.Method == http.MethodPost {
		fmt.Fprint(w, "Money transferred successfully!")
	} else {
		welcomeTemplate.Execute(w, nil)
	}
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

var welcomeTemplate = template.Must(template.New("").Parse(`
<!DOCTYPE html>
<html>
<head>
	<title>Welcome</title>
</head>
<body>
	<h1>Welcome to the vulnerable web app!</h1>
	<form method="post" action="/welcome">
		<input type="hidden" name="amount" value="1000">
		<input type="hidden" name="to" value="attacker">
		<input type="submit" value="Transfer Money">
	</form>
</body>
</html>
`))
