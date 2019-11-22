package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"path/filepath"

	"github.com/joho/godotenv"
	"golang.org/x/crypto/ssh"
	kh "golang.org/x/crypto/ssh/knownhosts"
)

// var servers = []string{"206.189.121.13"}
// var servers = []string{"206.189.121.13", "46.101.79.230"}

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		panic(err)
	}
	servers := strings.Split(os.Getenv("SERVERS"), ",")

	if len(servers) == 0 {

		log.Fatal("No servers found, expected SERVERS in env file")
	}

	sshpath := os.Getenv("SSH_PATH")

	if sshpath == "" {

		log.Fatal("No ssh path provived, expected SSH_PATH in env file")
	}

	user := "root"
	commands := []string{
		"hostname",
		"df /home | awk '{ print $5 }' | tail -n 1 | sed 's/%//'",
	}

	key, err := ioutil.ReadFile(filepath.FromSlash(sshpath + "/id_rsa"))
	if err != nil {
		log.Fatalf("unable to read private key: %v", err)
	}

	// Create the Signer for this private key.
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		log.Fatalf("unable to parse private key: %v", err)
	}

	hostKeyCallback, err := kh.New(filepath.FromSlash(sshpath + "/known_hosts"))
	if err != nil {

		log.Fatal("could not create hostkeycallback function: ", err)
	}

	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: hostKeyCallback,
	}

	for _, server := range servers {

		// Connect to the remote server and perform the SSH handshake.
		client, err := ssh.Dial("tcp", server+":22", config)
		if err != nil {
			log.Fatalf("unable to connect: %v", err)
		}
		defer client.Close()

		ss, err := client.NewSession()
		if err != nil {
			log.Fatal("unable to create SSH session: ", err)
		}
		defer ss.Close()

		stdin, err := ss.StdinPipe()
		if err != nil {
			panic(err)
		}
		stdout, err := ss.StdoutPipe()
		if err != nil {
			panic(err)
		}

		// Uncomment to store output in variable
		// var b bytes.Buffer
		// ss.Stdout = &b
		// ss.Stderr = &b

		// Enable system stdout
		// Comment these if you uncomment to store in variable
		// ss.Stdout = os.Stdout
		// ss.Stderr = os.Stderr

		// Start remote shell
		err = ss.Shell()
		if err != nil {
			log.Fatal(err)
		}

		// send the commands
		for _, cmd := range commands {
			_, err := stdin.Write([]byte(cmd + "\n"))
			if err != nil {
				log.Fatal(err)
			}

			out, err := read(stdout)
			if err != nil {
				log.Panic("error here ", err)
			}
			fmt.Printf("output of command `%s`: %s\n", cmd, *out)
		}

		_, err = stdin.Write([]byte("exit;\n"))
		if err != nil {
			log.Panic("error here ", err)
		}

		// Wait for sess to finish
		err = ss.Wait()
		if err != nil {
			log.Fatal("fatal here ", err)
		}
	}

}

var escapePrompt = []byte{'$', ' '}

func write(w io.WriteCloser, command string) error {
	_, err := w.Write([]byte(command + "\n"))
	return err
}

func read(r io.Reader) (*string, error) {
	var buf [64 * 1024]byte
	var t int
	for {
		n, err := r.Read(buf[t:])
		if err != nil {
			return nil, err
		}
		t += n
		// if isMatch(buf[:t], t, matchingByte) {
		stringResult := string(buf[:t])
		return &stringResult, nil
		// }
	}
}
