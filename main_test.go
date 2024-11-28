package main

import (
	"fmt"
	"github.com/DataDog/datadog-go/statsd"
	"math/rand"
	"testing"
	"time"
)

func TestReadMovies(t *testing.T) {
	if _, err := readMovies(); err != nil {
		t.Fatal(err)
	}
}

func TestGetCallerFuncName(t *testing.T) {

	for i := 0; i < 10; i++ {
		fmt.Println(getCurServID())
	}

	for i := 0; i < 10; i++ {
		fmt.Println(getNextServID())
	}

	fmt.Println(getCurServName())
	fmt.Println(getNextServName())

}

func TestDatadogStatsD(t *testing.T) {
	cli, err := statsd.New("localhost:8125", statsd.WithNamespace("com.guance.statsd_demo"),
		statsd.WithTags([]string{"service:statsd_demo", "username:zhangyi", "age:35", "gender:Male"}),
		statsd.WithBufferFlushInterval(time.Second*3),
	)
	if err != nil {
		t.Fatal(err)
	}

	defer cli.Close()

	for i := 0; i < 10; i++ {
		if err = cli.Count("request.count", int64(i)+1, []string{"path:/v1/ping", "statusCode: 201"}, 1); err != nil {
			t.Fatal(err)
		}

		if err = cli.Histogram("request.latency", 0.014*float64(i), []string{"path:/v1/profiling/input"}, 1); err != nil {
			t.Fatal(err)
		}

		if err = cli.Gauge("weather.temperature", 30+0.35*float64(rand.Intn(10)), []string{"city:Shanghai"}, 1); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Second * 2)
	}
}
