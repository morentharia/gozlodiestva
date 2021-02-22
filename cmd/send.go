/*
Copyright © 2021 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

//TODO: make it work without burp

import (
	// "fmt"
	// "log"

	"context"
	"os"
	"sync"

	"github.com/spf13/cobra"

	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

const (
	SemaphoreSize = 20
	CRLF          = "\r\n"
	ProxyAddr     = "localhost:8080"
	DefaultPort   = 443
	//TODO;
	UpdateContentLength = true
	DealTimeout         = time.Second * 10
	RWTimeout           = time.Second * 5
	WorkerPoolSize      = 30
)

func dialProxy(addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: DealTimeout}
	conn, err := d.Dial("tcp", ProxyAddr)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	for _, v := range []string{
		fmt.Sprintf("CONNECT %s HTTP/1.1\n\r", addr),
		CRLF + CRLF,
	} {
		// fmt.Printf("> %q\n", v)
		fmt.Fprint(conn, v)
	}

	r := bufio.NewReader(conn)
	s, err := r.ReadString('\n')
	if err != nil {
		return nil, errors.WithStack(err)
	}
	// fmt.Printf("< %q\n", s)
	if !strings.Contains(s, "200") {
		return nil, errors.WithStack(err)
	}
	return conn, nil
}

func ParseRawHTTPRequest(content string) (string, string, error) {
	var host string
	var res strings.Builder
	if content == "" {
		return "", "", errors.WithStack(errors.New("content == ''"))
	}

	log.WithField("content", content).Info("WTf")
	r := bufio.NewReader(strings.NewReader(content))
	st, err := r.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", "", errors.WithStack(err)
	}
	res.WriteString(strings.TrimSpace(st) + CRLF)

	for {
		h, err := r.ReadString('\n')
		h = strings.TrimSpace(h)
		if err != nil || h == "" {
			break
		}
		p := strings.SplitN(h, ":", 2)
		if len(p) != 2 {
			continue
		}

		if strings.ToLower(p[0]) == "content-length" {
			continue
		}

		if strings.ToLower(p[0]) == "host" {
			host = strings.TrimSpace(p[1])
		}
		res.WriteString(h + CRLF)
	}
	data, _ := ioutil.ReadAll(r)
	res.WriteString(fmt.Sprintf("Content-Length: %d%s", len(data), CRLF))
	res.WriteString(CRLF)
	res.Write(data)
	return host, res.String(), nil
}

func recvHttpResp(conn io.Reader) (string, error) {
	var res strings.Builder
	r := bufio.NewReader(io.TeeReader(conn, &res))
	_, err := r.ReadString('\n')
	if err != nil {
		return "", errors.WithStack(err)
	}

	cl := 0
	for {
		h, err := r.ReadString('\n')
		h = strings.TrimSpace(h)
		if err != nil || h == "" {
			break
		}

		p := strings.SplitN(h, ":", 2)
		if len(p) != 2 {
			continue
		}

		if strings.ToLower(p[0]) == "content-length" {
			cl, err = strconv.Atoi(strings.TrimSpace(p[1]))
			if err != nil {
				log.WithError(err).Error("")
				continue
			}
		}
	}
	if cl > 0 {
		b := make([]byte, cl)
		_, err = io.ReadAtLeast(r, b, cl)
		if err != nil {
			return "", errors.WithStack(err)
		}
	}
	return res.String(), nil
}

func SendRawRequest(content string) (string, error) {
	hostname, content, err := ParseRawHTTPRequest(content)
	if err != nil {
		return "", errors.WithStack(err)
	}
	conn, err := dialProxy(fmt.Sprintf("%s:%d", hostname, DefaultPort))
	if err != nil {
		return "", errors.WithStack(err)
	}
	defer conn.Close()

	roots, err := x509.SystemCertPool()
	if err != nil {
		return "", errors.WithStack(err)
	}
	conf := &tls.Config{RootCAs: roots, InsecureSkipVerify: true}
	connTLS := tls.Client(conn, conf)

	connTLS.SetDeadline(time.Now().Add(RWTimeout))
	_, err = io.WriteString(connTLS, string(content))
	if err != nil {
		return "", errors.WithStack(err)
	}
	connTLS.SetDeadline(time.Now().Add(RWTimeout))
	rawresp, err := recvHttpResp(connTLS)
	if err != nil {
		return "", errors.WithStack(err)
	}
	return rawresp, nil
}

// sendCmd represents the send command
var sendCmd = &cobra.Command{
	Use:   "send",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		ctx, cancel := context.WithCancel(context.Background())
		wg := &sync.WaitGroup{}
		defer wg.Wait()
		defer cancel()
		jobs := make(chan string, 2*WorkerPoolSize)
		results := make(chan string, 2*WorkerPoolSize)

		wg.Add(WorkerPoolSize)
		for id := 0; id < WorkerPoolSize; id++ {
			go func(id int) {
				defer wg.Done()
				for {
					select {
					case dat := <-jobs:
						var res string
						// fmt.Println("worker", id, "processing job", dat)
						// time.Sleep(time.Second)
						res, err := SendRawRequest(dat)
						if err != nil {
							log.Printf("err = %+v\n", err)
							// log.WithError(err).Error("fuck")
						}
						select {
						case results <- res:
						case <-ctx.Done():
							return
						}
					case <-ctx.Done():
						return
					}
				}
			}(id)
		}

		for i := 0; i < len(args); i++ {
			dat, err := ioutil.ReadFile(args[i])
			if err != nil {
				log.WithError(err).Error("ReadFile")
				os.Exit(1)
			}
			fmt.Print(string(dat))
			jobs <- string(dat)
		}
		close(jobs)

		for i := 0; i < len(args); i++ {
			log.Printf("result = %#v\n", <-results)
		}
	},
}

func init() {
	rootCmd.AddCommand(sendCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// sendCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// sendCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
