// main.js

async function login() {
    const username = document.getElementById("username").value.trim();
    const password = document.getElementById("password").value.trim();

    if (!username || !password) {
        alert("Please enter both username and password.");
        return;
    }

    try {
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (response.ok) {
            alert("Login successful!");

            // Redirect based on role
            if (data.role === 'admin') {
                window.location.href = "/admin";
            } else {
                window.location.href = "/upload";
            }

            // Optionally save user session
            localStorage.setItem("loggedInUser", username);
        } else {
            alert(data.message || "Login failed.");
        }

    } catch (error) {
        //console.error("Login error:", error);
       // alert("An error occurred while trying to login.");
    }
}
