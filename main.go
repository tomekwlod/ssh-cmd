package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"path/filepath"

	"github.com/joho/godotenv"
	"golang.org/x/crypto/ssh"
	kh "golang.org/x/crypto/ssh/knownhosts"
)

type RemoteEntities struct {
	Droplets []Droplets `json:"droplets"`
}
type Droplets struct {
	ID       int     `json:"id"`
	Name     string  `json:"name"`
	Networks Network `json:"networks"`
}
type Network struct {
	Version []V4 `json:"v4"`
}
type V4 struct {
	IP string `json:"ip_address"`
}

// type IP struct {
// 	IP string `json:"ip_address"`
// }

func main() {

	err := godotenv.Load(".env")
	if err != nil {
		panic(err)
	}
	// servers := strings.Split(os.Getenv("SERVERS"), ",")
	s := servers()

	if len(s.Droplets) == 0 {

		log.Fatal("No servers found, expected SERVERS in env file")
	}

	sshpath := os.Getenv("SSH_PATH")

	if sshpath == "" {

		log.Fatal("No ssh path provived, expected SSH_PATH in env file")
	}

	user := "root"
	commands := []string{
		// "hostname",
		"df /home | awk '{ print $5 }' | tail -n 1 | sed 's/%//'",
		// "exit",
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

	for _, server := range s.Droplets {

		ip := server.Networks.Version[0].IP
		name := server.Name
		// ip := "134.209.26.132"
		// name := "stan"

		// if name == "angelita" {

		// 	continue
		// }
		// if name == "chainsaw" {

		// 	continue
		// }
		// if name == "chef" {

		// 	continue
		// }
		// if name == "kenny" {

		// 	continue
		// }
		// if name == "sftp" {

		// 	continue
		// }
		// if name == "es" {

		// 	continue
		// }
		// if name == "falcon" {

		// 	continue
		// }
		// if name == "bebe" {

		// 	continue
		// }
		// if name == "timon" {

		// 	continue
		// }

		// Connect to the remote server and perform the SSH handshake.
		client, err := ssh.Dial("tcp", ip+":22", config)
		if err != nil {
			log.Fatalf("unable to connect: %v", err)
		}
		defer client.Close()

		ss, err := client.NewSession()
		if err != nil {
			log.Fatal("unable to create SSH session: ", err)
		}
		defer ss.Close()

		// stdin, err := ss.StdinPipe()
		// if err != nil {
		// 	panic(err)
		// }
		// stdout, err := ss.StdoutPipe()
		// if err != nil {
		// 	panic(err)
		// }

		stdin, err := ss.StdinPipe()
		if err != nil {
			log.Panicf("Unable to setup stdin for session: %v", err)
		}
		go io.Copy(stdin, os.Stdin)

		stdout, err := ss.StdoutPipe()
		if err != nil {
			log.Panicf("Unable to setup stdout for session: %v", err)
		}
		go io.Copy(os.Stdout, stdout)

		stderr, err := ss.StderrPipe()
		if err != nil {
			log.Panicf("Unable to setup stderr for session: %v", err)
		}
		go io.Copy(os.Stderr, stderr)

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

			fmt.Printf("Executing command`" + cmd + "` ====>> ")

			// _, err := stdin.Write([]byte(cmd + "\n"))
			// if err != nil {
			// 	log.Fatal(err)
			// }

			_, err = fmt.Fprintf(stdin, "%s\n", cmd)
			if err != nil {
				log.Fatal(err)
			}

			// out, err := read(stdout)
			// if err != nil {
			// 	log.Panic("error here ", err)
			// }

			// fmt.Printf("%s\n", *out)

		}

		fmt.Println("Closing " + name)
		_, err = stdin.Write([]byte("exit\n"))
		if err != nil {
			log.Fatal("error here ee", err)
		}

		// err = ss.Close()
		// if err != nil {
		// 	log.Panic("error here ", err)
		// }

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

func servers() (d RemoteEntities) {

	url := "https://api.digitalocean.com/v2/droplets?page=1&per_page=20"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatal(err)
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("cache-control", "no-cache")
	req.Header.Add("Authorization", "Bearer 7df2637c503ebced89e7d7b1dc40b16066007669d0edc007d375b9726a0683ca")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	defer res.Body.Close()

	// Try to decode the request body into the struct. If there is an error,
	// respond to the client with the error message and a 400 status code.
	err = json.NewDecoder(res.Body).Decode(&d)
	if err != nil {
		log.Fatal(err)
	}

	// printing pretty
	// b, err := json.MarshalIndent(d, "", "  ")
	// if err != nil {
	// 	fmt.Println("error:", err)
	// }
	// os.Stdout.Write(b)

	return d
}
