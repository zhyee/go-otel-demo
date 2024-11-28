package main

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.10.0"
	"io"
	"log"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/GuanceCloud/oteldatadogtie"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	otelmetric "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	"gopkg.in/DataDog/dd-trace-go.v1/profiler"
)

const BaseServiceName = "go-otel-demo"

var serviceId = func() *atomic.Int64 {
	return &atomic.Int64{}
}()

var tracer trace.Tracer

func resetServiceID() {
	serviceId.Store(0)
}

func getCurServID() string {
	return strconv.FormatInt(serviceId.Load(), 10)
}

func getNextServID() string {
	serviceId.Add(1)
	return getCurServID()
}

func getCurServName() string {
	return fmt.Sprintf("%s-%s", BaseServiceName, getCurServID())
}

func getNextServName() string {
	return fmt.Sprintf("%s-%s", BaseServiceName, getNextServID())
}

type Movie struct {
	Title       string  `json:"title"`
	VoteAverage float64 `json:"vote_average"`
	ReleaseDate string  `json:"release_date"`
}

func GetCallerFuncName() string {
	pcs := make([]uintptr, 1)
	if runtime.Callers(2, pcs) < 1 {
		return ""
	}
	frame, _ := runtime.CallersFrames(pcs).Next()

	base := filepath.Base(frame.Function)

	if strings.ContainsRune(base, '.') {
		return filepath.Ext(base)[1:]
	}
	return base
}

func readMovies() ([]Movie, error) {
	f, err := os.Open("./movies5000.json.gz")
	if err != nil {
		return nil, fmt.Errorf("open movies data file fail: %w", err)
	}
	defer f.Close()
	r, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("gzip new reader from *FILE fail: %w", err)
	}
	defer r.Close()

	var movies []Movie

	if err := json.NewDecoder(r).Decode(&movies); err != nil {
		return nil, fmt.Errorf("json unmarshal fail: %w", err)
	}

	return movies, nil
}

func isENVTrue(key string) bool {
	val := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	switch val {
	case "", "0", "false":
		return false
	}
	return true
}

func sendHtmlRequest(ctx context.Context, bodyText string, servName string) {
	_, span := tracer.Start(ctx, GetCallerFuncName(),
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(attribute.String("service.name", servName)),
		trace.WithTimestamp(time.Now()),
		trace.WithLinks())
	defer span.End()

	req, err := http.NewRequest(http.MethodGet, "https://tv189.com/", strings.NewReader(strings.Repeat(bodyText, 1000)))

	if err != nil {
		log.Println(err)
		return
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Println(err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Println(err)
		return
	}

	log.Println("response body len: ", len(body))
}

func fibonacci(ctx context.Context, n int, servName string) int {
	if n <= 2 {
		return 1
	}
	if n%31 == 0 {
		return fibonacciWithTrace(ctx, n-1, servName) + fibonacciWithTrace(ctx, n-2, servName)
	} else if n%37 == 0 {
		return fibonacciWithTrace(ctx, n-1, servName) + fibonacciWithTrace(ctx, n-2, servName)
	}
	return fibonacci(ctx, n-1, servName) + fibonacci(ctx, n-2, servName)
}

func fibonacciWithTrace(ctx context.Context, n int, servName string) int {
	var newCtx context.Context
	var span trace.Span
	newCtx, span = tracer.Start(ctx, GetCallerFuncName(), trace.WithAttributes(attribute.Int("n", n),
		attribute.String("service.name", servName)))
	defer span.End()

	return fibonacci(newCtx, n-1, servName) + fibonacci(newCtx, n-2, servName)
}

func httpReqWithTrace(ctx context.Context) {
	var newCtx context.Context
	var span trace.Span
	newCtx, span = tracer.Start(ctx, GetCallerFuncName(),
		trace.WithAttributes(attribute.String("service.name", getNextServName())))
	defer span.End()

	bodyText := `
黄河远上白云间，一片孤城万仞山。
羌笛何须怨杨柳，春风不度玉门关。
少小离家老大回，乡音无改鬓毛衰。
儿童相见不相识，笑问客从何处来。
`

	for i := 0; i < 10; i++ {
		sendHtmlRequest(newCtx, bodyText, getCurServName())
	}
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	ctx := context.Background()

	exporter, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithInsecure(),
		//otlptracegrpc.WithEndpoint("localhost:4317"),
	)

	//exporter, err := otlptracehttp.New(ctx,
	//	otlptracehttp.WithEndpointURL("http://127.0.0.1:9529/otel/v1/trace"),
	//	otlptracehttp.WithInsecure(),
	//	otlptracehttp.WithCompression(otlptracehttp.NoCompression),
	//)
	if err != nil {
		log.Fatalf("unable to init exporter: %v \n", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithResource(
			resource.NewSchemaless(
				//attribute.String("service.name", getNextServName()),
				semconv.ServiceNameKey.String(getCurServName()),
				semconv.ServiceVersionKey.String("v3.4.55"),
			),
		),
		sdktrace.WithBatcher(exporter, sdktrace.WithBatchTimeout(time.Second*5)),
	)

	tp2 := oteldatadogtie.Wrap(tp)
	defer tp2.Shutdown(ctx)

	//tp := oteldatadogtie.NewTracerProvider(sdktrace.WithBatcher(exporter, sdktrace.WithBatchTimeout(time.Second)))
	//defer tp.Shutdown(ctx)

	otel.SetTracerProvider(tp2)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) {
		log.Println("otel encounters error: ", err)
	}))

	tracer = otel.Tracer("go-otel-demo",
		trace.WithInstrumentationAttributes(attribute.String("service.name", BaseServiceName)),
		trace.WithInstrumentationVersion("v3.4.99"),
	)

	//metricExporter, err := stdoutmetric.New(stdoutmetric.WithPrettyPrint())

	metricExporter, err := otlpmetricgrpc.New(ctx,
		otlpmetricgrpc.WithInsecure(),
		//otlpmetricgrpc.WithEndpoint("localhost:4317"),
	)

	if err != nil {
		log.Fatal(err)
	}

	metricProvider := metric.NewMeterProvider(
		metric.WithReader(metric.NewPeriodicReader(metricExporter, metric.WithInterval(time.Second*15))))

	defer metricProvider.Shutdown(context.Background())

	otel.SetMeterProvider(metricProvider)

	meter := otel.Meter("otel-metrics")

	reqCounter, err := meter.Int64Counter("request.count", otelmetric.WithDescription("total request count"))
	if err != nil {
		log.Fatal(err)
	}

	reqLatency, err := meter.Float64Histogram("request.latency",
		otelmetric.WithUnit("s"), otelmetric.WithDescription("req duration statistics"),
		otelmetric.WithExplicitBucketBoundaries(0.01, 0.05, 0.1, 0.3, 0.5, 1.0),
	)

	if isENVTrue("DD_PROFILING_ENABLED") {
		options := []profiler.Option{
			profiler.WithProfileTypes(
				profiler.CPUProfile,
				profiler.HeapProfile,

				// The profiles below are disabled by default to keep overhead
				// low, but can be enabled as needed.
				profiler.BlockProfile,
				profiler.MutexProfile,
				profiler.GoroutineProfile,
				profiler.MetricsProfile,
			),
			//profiler.WithAgentAddr("127.0.0.1:9529"),
			profiler.WithService("go-otel-demo"),
			profiler.WithEnv("pre-release"),
			profiler.WithVersion("v0.1.2"),
		}

		options = append(options, profiler.WithTags(oteldatadogtie.TagRuntimeID))

		err := profiler.Start(options...)

		if err != nil {
			log.Fatal(err)
		}

		defer profiler.Stop()
	}

	router := gin.New()
	//router.Use(gintrace.Middleware("go-otel-demo"))

	// Access-Control-*
	router.Use(cors.New(cors.Config{
		AllowAllOrigins:  true,
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"},
		AllowCredentials: true,
		AllowHeaders:     []string{"*"},
		MaxAge:           time.Hour * 24,
	}))

	router.GET("/movies", func(ctx *gin.Context) {
		log.Println("headers: ")
		for k, v := range ctx.Request.Header {
			log.Printf("%s:%s\n", k, strings.Join(v, ","))
		}

		start := time.Now()

		resetServiceID()

		reqCounter.Add(ctx, 1, otelmetric.WithAttributes(attribute.String("request-uri", ctx.Request.RequestURI)))

		defer func() {
			statusCode := ctx.Writer.Status()
			reqLatency.Record(ctx, time.Since(start).Seconds(), otelmetric.WithAttributes(attribute.Int("http-status-code", statusCode)))
		}()

		var newCtx context.Context

		otelCtx := otel.GetTextMapPropagator().Extract(ctx.Request.Context(), propagation.HeaderCarrier(ctx.Request.Header))

		var span trace.Span
		newCtx, span = tracer.Start(otelCtx, "get_movies",
			trace.WithAttributes(attribute.String("service", getNextServName())))
		defer span.End()

		var wg sync.WaitGroup
		wg.Add(2)

		go func(ctx context.Context) {
			defer wg.Done()
			param := 40
			log.Printf("fibonacci(%d) = %d\n", param, fibonacci(ctx, param, getNextServName()))
			log.Printf("fibonacci(%d) = %d\n", param, fibonacci(ctx, param, getNextServName()))
		}(newCtx)

		go func(ctx context.Context) {
			defer wg.Done()
			httpReqWithTrace(ctx)
		}(newCtx)

		q := ctx.Request.FormValue("q")

		movies, err := readMovies()
		if err != nil {
			log.Println("unable to read movies:", err)
			ctx.Writer.WriteHeader(http.StatusInternalServerError)
			return
		}

		//func() {
		//	request, err := http.NewRequestWithContext(tracer.ContextWithSpan(ctx.Request.Context(), span),
		//		http.MethodPost, "http://127.0.0.1:5888/foobar", nil)
		//	if err != nil {
		//		log.Println("unable to new request: ", err)
		//		return
		//	}
		//	err = tracer.Inject(span.Context(), tracer.HTTPHeadersCarrier(request.Header))
		//	if err != nil {
		//		log.Println("unable to inject span to request: ", err)
		//		return
		//	}
		//	resp, err := http.DefaultClient.Do(request)
		//	if err != nil {
		//		log.Println("unable to request go-http-client")
		//		return
		//	}
		//	defer resp.Body.Close()
		//
		//	body, err := io.ReadAll(resp.Body)
		//	if err != nil {
		//		log.Println("unable to read request body: ", err)
		//	}
		//
		//	fmt.Println("response: ", string(body))
		//}()

		sort.Slice(movies, func(i, j int) bool {
			time.Sleep(time.Microsecond * 10)
			t1, err := time.Parse("2006-01-02", movies[i].ReleaseDate)
			if err != nil {
				return false
			}
			t2, err := time.Parse("2006-01-02", movies[j].ReleaseDate)
			if err != nil {
				return true
			}
			return t1.After(t2)
		})

		if q != "" {
			q = strings.ToUpper(q)
			matchCount := 0
			for idx, m := range movies {
				if strings.Contains(strings.ToUpper(m.Title), q) && idx != matchCount {
					movies[matchCount] = movies[idx]
					matchCount++
				}
			}
			movies = movies[:matchCount]
		}

		encoder := json.NewEncoder(ctx.Writer)
		encoder.SetIndent("", "    ")
		if err := encoder.Encode(movies); err != nil {
			log.Printf("encode into json fail: %s", err)
			ctx.Writer.WriteHeader(http.StatusInternalServerError)
		}
		wg.Wait()
	})

	pprofIndex := func(ctx *gin.Context) {
		pprof.Index(ctx.Writer, ctx.Request)
	}

	router.GET("/debug/pprof", func(ctx *gin.Context) {
		ctx.Redirect(http.StatusMovedPermanently, "/debug/pprof/")
	})

	pg := router.Group("/debug/pprof")
	pg.GET("/", pprofIndex)
	pg.GET("/:name", pprofIndex)
	pg.GET("/cmdline", func(ctx *gin.Context) {
		pprof.Cmdline(ctx.Writer, ctx.Request)
	})
	pg.GET("/profile", func(ctx *gin.Context) {
		pprof.Profile(ctx.Writer, ctx.Request)
	})
	pg.GET("/symbol", func(ctx *gin.Context) {
		pprof.Symbol(ctx.Writer, ctx.Request)
	})
	pg.GET("/trace", func(ctx *gin.Context) {
		pprof.Trace(ctx.Writer, ctx.Request)
	})

	serv := &http.Server{
		Addr:    ":8080",
		Handler: router,
	}

	go func() {
		sig := make(chan os.Signal, 16)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
		<-sig
		newCtx, fn := context.WithTimeout(context.Background(), 5*time.Second)
		defer fn()
		if err := serv.Shutdown(newCtx); err != nil {
			log.Println("unable to close http server: ", err)
		}
	}()

	if err = serv.ListenAndServe(); err != nil {
		if errors.Is(err, http.ErrServerClosed) {
			log.Println("http server closed")
			return
		}
		log.Fatal(err)
	}
}
