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
	CRLF           = "\r\n"
	ProxyAddr      = "localhost:8080"
	DefaultPort    = 443
	DealTimeout    = time.Second * 120
	RWTimeout      = time.Second * 60
	WorkerPoolSize = 200
	//TODO;
	// UpdateContentLength = true
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
		conn.SetDeadline(time.Now().Add(RWTimeout))
		fmt.Fprint(conn, v)
	}

	conn.SetDeadline(time.Now().Add(RWTimeout))
	r := bufio.NewReader(conn)
	s, err := r.ReadString('\n')
	if err != nil && err != io.EOF {
		return nil, errors.WithStack(err)
	}
	// fmt.Printf("< %q\n", s)
	if !strings.Contains(s, "200") {
		return nil, errors.WithStack(err)
	}
	return conn, nil
}

func ParseRawHTTPRequest(content string) (string, string, error) {
	// TODO: add no gzip header
	var host string
	var res strings.Builder
	if len(content) == 0 {
		return "", "", errors.WithStack(errors.New("content == ''"))
	}

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

//TODO: вписывай файло в __resp.http в той же папке
func SendRawRequest(content string) (string, error) {
	hostname, content, err := ParseRawHTTPRequest(content)
	if err != nil {
		return "", errors.WithStack(err)
	}
	// TODO: может впилить какой нибудь аля pool коннектов к прокси
	// conn, err := dialProxy(fmt.Sprintf("%s:%d", hostname, DefaultPort))
	// if err != nil {
	// 	return "", errors.WithStack(err)
	// }
	// defer conn.Close()

	d := net.Dialer{Timeout: DealTimeout}
	conn, err := d.Dial("tcp", hostname+":443")
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
	defer connTLS.Close()

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
		// defer cancel()
		jobs := make(chan string, 100)
		results := make(chan string, 100)

		wg.Add(WorkerPoolSize)
		for id := 0; id < WorkerPoolSize; id++ {
			go func(id int) {
				defer wg.Done()
				for {
					select {
					case dat := <-jobs:
						var res string
						// log.Info(dat[:80])
						res, err := SendRawRequest(dat)
						if err != nil {
							log.Printf("err = %+v\n", err)
							log.WithError(err).Error("SendRawRequest")
							res = fmt.Sprintf("ERROR: %s", err)
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

		go func(args []string) {
			// for {
			// 	log.Printf("result = %#v\n", (<-results)[:60])
			// }
			for i := 0; i < len(args); i++ {
				log.Printf("result(%d) = %#v\n", i, (<-results)[:20])
			}
			cancel()
		}(args)

		log.Printf("len(args) = %#v\n", len(args))

		for i := 0; i < len(args); i++ {
			dat, err := ioutil.ReadFile(args[i])
			if err != nil {
				log.WithError(err).Error("ReadFile")
				os.Exit(1)
			}
			jobs <- string(dat)
			log.Printf("i = %#v filename = %#v\n", i, args[i])
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
