package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/tomekwlod/utils"

	"github.com/joho/godotenv"
	"golang.org/x/crypto/ssh"
	kh "golang.org/x/crypto/ssh/knownhosts"
)

// time out when a machine is off
// sort out the order of the results

type RemoteEntities struct {
	Droplets []Droplets `json:"droplets"`
}
type Droplets struct {
	ID       int      `json:"id"`
	Name     string   `json:"name"`
	Status   string   `json:"status"`
	Networks Network  `json:"networks"`
	Tags     []string `json:"tags"`
}
type Network struct {
	Version []V4 `json:"v4"`
}
type V4 struct {
	IP string `json:"ip_address"`
}
type Server struct {
	IP, Port, Name string
}

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		panic(err)
	}

	s := servers()

	if len(s.Droplets) == 0 {

		log.Fatal("No servers found, expected SERVERS in env file")
	}

	sshpath := os.Getenv("SSH_PATH")

	if sshpath == "" {

		log.Fatal("No ssh path provived, expected SSH_PATH in env file (where are your ssh files?)")
	}

	user := "root"
	// commands := []string{
	// 	// "hostname",
	// 	"df /home | awk '{ print $5 }' | tail -n 1 | sed 's/%//'",
	// 	// "exit",
	// }

	result := make(chan string, 10)
	timeout := time.After(10 * time.Second)

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

	var servers []Server

	for _, droplet := range s.Droplets {

		// just to exclude the kubernetes nodes
		if utils.SliceContains(droplet.Tags, "k8s") {

			continue
		}

		if droplet.Status == "off" {

			continue
		}

		servers = append(servers, Server{droplet.Networks.Version[0].IP, "22", droplet.Name})
	}

	log.Printf("%d servers available\n", len(s.Droplets))

	for _, server := range servers {

		go func(ip, port, hostname string, cnfg *ssh.ClientConfig) {

			cmd := "df /home | awk '{ print $5 }' | tail -n 1 | sed 's/%//'"

			result <- executeCmd(cmd, ip+":"+port, hostname, cnfg)

		}(server.IP, server.Port, server.Name, config)
	}

	for range servers {
		select {
		case res := <-result:
			fmt.Printf("%s", res)
		case <-timeout:
			fmt.Println("Timed out!")
			return
		}
	}
}

// type SignerContainer struct {
// 	signers []ssh.Signer
// }

// func (t *SignerContainer) Key(i int) (key ssh.PublicKey, err error) {
// 	if i >= len(t.signers) {
// 		return
// 	}
// 	key = t.signers[i].PublicKey()
// 	return
// }
// func (t *SignerContainer) Sign(i int, rand io.Reader, data []byte) (sig []byte, err error) {
// 	if i >= len(t.signers) {
// 		return
// 	}
// 	sig, err = t.signers[i].Sign(rand, data)
// 	return
// }

// func makeSigner(keyname string) (signer ssh.Signer, err error) {
// 	key, err := ioutil.ReadFile(filepath.FromSlash(keyname))
// 	if err != nil {
// 		log.Fatalf("unable to read private key: %v", err)
// 	}
// 	signer, err = ssh.ParsePrivateKey(key)

// 	if err != nil {

// 		return nil, err
// 	}

// 	return
// }

// func makeKeyring() ssh.AuthMethod {
// 	// signer := ssh.Signer{}
// 	key := "/Users/youruser/.ssh/id_rsa"

// 	// for _, keyname := range keys {
// 	signer, err := makeSigner(key)
// 	if err != nil {
// 		panic(err)
// 	}
// 	// }

// 	return ssh.PublicKeys(signer)
// 	// return ssh.ClientAuthKeyring(&SignerContainer{signers})
// }

func executeCmd(command, addr, hostname string, config *ssh.ClientConfig) string {

	conn, err := ssh.Dial("tcp", fmt.Sprintf("%s", addr), config)
	if err != nil {

		log.Printf("[%s] Couldn't get into this host. Try to ssh manually first\n", hostname)

		return ""
	}

	session, err := conn.NewSession()
	defer session.Close()
	if err != nil {
		panic(err)
	}

	var stdoutBuf bytes.Buffer
	session.Stdout = &stdoutBuf
	session.Run(command)

	perc, _ := strconv.Atoi(strings.Trim(stdoutBuf.String(), "\t \n"))

	alertSign := "\t"
	if perc >= 80 {
		alertSign = "!!\t"

	}

	return fmt.Sprintf("%s %s -> %s", alertSign, hostname, stdoutBuf.String())
}

func servers() (d RemoteEntities) {

	url := "https://api.digitalocean.com/v2/droplets?page=1&per_page=20"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatal(err)
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("cache-control", "no-cache")
	req.Header.Add("Authorization", "Bearer "+os.Getenv("DO_TOKEN"))

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer res.Body.Close()

	// bb, err := utils.BodyToString(res.Body)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// fmt.Println("bb->", bb)

	// Try to decode the request body into the struct. If there is an error,
	// respond to the client with the error message and a 400 status code.
	err = json.NewDecoder(res.Body).Decode(&d)
	if err != nil {
		log.Fatalf("An error occured\n'%v'", err)
	}

	// rr, err := utils.PrettyJson(d)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// fmt.Println("rr->", rr)

	return d
}
