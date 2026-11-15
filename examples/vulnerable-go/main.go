package main

import (
	"fmt"
	"net/http"
	"os/exec"
)

// This application is intentionally vulnerable and must never be deployed.
func commandHandler(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	out, _ := exec.Command("sh", "-c", cmd).CombinedOutput()
	_, _ = w.Write(out)
}

func main() {
	http.HandleFunc("/command", commandHandler)
	fmt.Println(http.ListenAndServe("127.0.0.1:18080", nil))
}
