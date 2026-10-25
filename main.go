package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	codebuildTypes "github.com/aws/aws-sdk-go-v2/service/codebuild/types"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/joho/godotenv"

	"github.com/moby/moby/api/types/registry"
	"github.com/moby/moby/client"
)

// ANSI color helpers
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
)

type TokenResponse struct {
	AccessKeyId     string `json:"accessKeyId"`
	SecretAccessKey string `json:"secretAccessKey"`
	SessionToken    string `json:"sessionToken"`
	RegistryUri     string `json:"registryUri"`
	RepositoryPath  string `json:"repositoryPath"`
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Println("No .env file found, relying on system environment variables")
	}
	ctx := context.Background()

	// 0. Parse Command Line Arguments
	imageFlag := flag.String("image", "project:latest", "Target local Docker image to scan (e.g. project:latest)")
	userFlag := flag.String("user", "user-1", "Tenant/User identifier")
	verboseFlag := flag.Bool("verbose", false, "Enable detailed debug and raw engine output")
	languageFlag := flag.String("lang", "javascript-typescript", "The language to scan (e.g., python, go, java-kotlin)")
	buildCmdFlag := flag.String("build-cmd", "", "The build command for compiled languages (e.g., 'make' or 'go build')")
	querySuiteFlag := flag.String("query-suite", "security-extended", "CodeQL suite: code-scanning, security-extended, or security-and-quality")
	requireTypescriptFlag := flag.Bool("require-typescript", false, "Require raw application TypeScript in the extracted image source")
	flag.BoolVar(verboseFlag, "v", false, "Shorthand for --verbose")
	failOnVulnFlag := flag.Bool("fail-on-vuln", true, "Exit with non-zero code if security issues are discovered")
	sarifFlag := flag.String("sarif", "", "Read a local SARIF report without contacting AWS or Docker")
	flag.Parse()
	switch *querySuiteFlag {
	case "code-scanning", "security-extended", "security-and-quality":
	default:
		log.Fatal("Invalid --query-suite: use code-scanning, security-extended, or security-and-quality")
	}
	if *sarifFlag != "" {
		body, err := os.ReadFile(*sarifFlag)
		if err != nil {
			log.Fatalf("Failed reading SARIF report: %v", err)
		}
		os.Exit(printReport(os.Stdout, body, *failOnVulnFlag, *verboseFlag))
	}

	logStep := func(step int, total int, message string) {
		fmt.Printf("%s[%d/%d]%s %s%s%s\n", colorCyan, step, total, colorReset, colorBold, message, colorReset)
	}

	debugLog := func(format string, a ...any) {
		if *verboseFlag {
			fmt.Printf(colorDim+"[DEBUG] "+format+colorReset+"\n", a...)
		}
	}

	lambdaURL := os.Getenv("LAMBDA_URL")
	bucketName := os.Getenv("BUCKET_NAME")
	projectName := "code-scanner"

	// 1. Fetch Temporary STS Credentials from Lambda
	logStep(1, 4, "Authenticating with Token Vendor...")
	requestBody, _ := json.Marshal(map[string]string{
		"userId": *userFlag,
	})

	resp, err := http.Post(lambdaURL, "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		log.Fatalf("%sFailed to connect to authentication endpoint: %v%s", colorRed, err, colorReset)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("%sAuthentication failed with status code: %d%s", colorRed, resp.StatusCode, colorReset)
	}

	var tokens TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		log.Fatalf("%sFailed to decode token response: %v%s", colorRed, err, colorReset)
	}

	remoteTag := fmt.Sprintf("%s/%s:latest", tokens.RegistryUri, tokens.RepositoryPath)
	debugLog("Assumed temporary role credentials successfully. Target tag: %s", remoteTag)

	// 2. Configure AWS SDK
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion("ap-south-2"),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			tokens.AccessKeyId,
			tokens.SecretAccessKey,
			tokens.SessionToken,
		)),
	)
	if err != nil {
		log.Fatalf("%sFailed to configure AWS SDK: %v%s", colorRed, err, colorReset)
	}

	// 3. Authenticate with ECR and Tag/Push Docker Image
	logStep(2, 4, fmt.Sprintf("Pushing container image to ECR (%s)...", *imageFlag))
	ecrClient := ecr.NewFromConfig(cfg)
	authOutput, err := ecrClient.GetAuthorizationToken(ctx, &ecr.GetAuthorizationTokenInput{})
	if err != nil {
		log.Fatalf("%sFailed to acquire ECR auth token: %v%s", colorRed, err, colorReset)
	}

	authData := authOutput.AuthorizationData[0]
	decodedToken, _ := base64.StdEncoding.DecodeString(*authData.AuthorizationToken)
	password := strings.TrimPrefix(string(decodedToken), "AWS:")

	cli, err := client.New(client.FromEnv)
	if err != nil {
		log.Fatalf("%sFailed to initialize local Docker client: %v%s", colorRed, err, colorReset)
	}

	if _, err := cli.ImageTag(ctx, client.ImageTagOptions{
		Source: *imageFlag,
		Target: remoteTag,
	}); err != nil {
		log.Fatalf("%sFailed to tag local image '%s': %v%s", colorRed, *imageFlag, err, colorReset)
	}

	authConfig := registry.AuthConfig{
		Username:      "AWS",
		Password:      password,
		ServerAddress: tokens.RegistryUri,
	}
	encodedAuth, _ := json.Marshal(authConfig)
	authStr := base64.URLEncoding.EncodeToString(encodedAuth)

	if err := pushWithRetry(ctx, func(pushCtx context.Context) (io.ReadCloser, error) {
		return cli.ImagePush(pushCtx, remoteTag, client.ImagePushOptions{RegistryAuth: authStr})
	}, os.Stdout, *verboseFlag, []time.Duration{2 * time.Second, 4 * time.Second}); err != nil {
		log.Fatalf("%sDocker push failed: %v%s", colorRed, err, colorReset)
	}

	// 4. Trigger CodeBuild Security Scan
	logStep(3, 4, "Triggering CodeQL security analysis...")
	cbClient := codebuild.NewFromConfig(cfg)
	typescriptRequirement := "0"
	if *requireTypescriptFlag {
		typescriptRequirement = "1"
	}

	startBuildResp, err := cbClient.StartBuild(ctx, &codebuild.StartBuildInput{
		ProjectName: &projectName,
		EnvironmentVariablesOverride: []codebuildTypes.EnvironmentVariable{
			{
				Name:  aws.String("IMAGE_URI"),
				Value: aws.String(remoteTag),
				Type:  codebuildTypes.EnvironmentVariableTypePlaintext,
			},
			{
				Name:  aws.String("LANGUAGE"),
				Value: aws.String(*languageFlag),
				Type:  codebuildTypes.EnvironmentVariableTypePlaintext,
			},
			{
				Name:  aws.String("BUILD_COMMAND"),
				Value: aws.String(*buildCmdFlag),
				Type:  codebuildTypes.EnvironmentVariableTypePlaintext,
			},
			{
				Name:  aws.String("CODEQL_SUITE"),
				Value: aws.String(*querySuiteFlag),
				Type:  codebuildTypes.EnvironmentVariableTypePlaintext,
			},
			{
				Name:  aws.String("REQUIRE_TYPESCRIPT"),
				Value: aws.String(typescriptRequirement),
				Type:  codebuildTypes.EnvironmentVariableTypePlaintext,
			},
		},
	})
	if err != nil {
		log.Fatalf("%sFailed to start CodeBuild scan: %v%s", colorRed, err, colorReset)
	}

	buildID := *startBuildResp.Build.Id
	debugLog("CodeBuild job started with ID: %s", buildID)

	// Poll CodeBuild status with safe intervals
	fmt.Print("   Analysis in progress")
	for {
		batchResp, err := cbClient.BatchGetBuilds(ctx, &codebuild.BatchGetBuildsInput{
			Ids: []string{buildID},
		})
		if err != nil {
			log.Fatalf("\n%sFailed checking build status: %v%s", colorRed, err, colorReset)
		}

		status := batchResp.Builds[0].BuildStatus
		if status == codebuildTypes.StatusTypeInProgress {
			fmt.Print(".")
			time.Sleep(10 * time.Second)
			continue
		}

		fmt.Println()
		if status != codebuildTypes.StatusTypeSucceeded {
			log.Fatalf("%sSecurity scan failed with status: %s. Check CodeBuild console for logs.%s", colorRed, status, colorReset)
		}
		break
	}

	// 5. Download and Parse SARIF Report
	logStep(4, 4, "Retrieving and parsing security report...")
	s3Key := fmt.Sprintf("reports/%s/codeql-scan-%s.sarif", *userFlag, buildID)
	debugLog("Fetching report from s3://%s/%s", bucketName, s3Key)

	s3Client := s3.NewFromConfig(cfg)
	s3Resp, err := s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(s3Key),
	})
	if err != nil {
		log.Fatalf("%sFailed to download SARIF report from S3: %v%s", colorRed, err, colorReset)
	}
	defer s3Resp.Body.Close()

	bodyBytes, err := io.ReadAll(s3Resp.Body)
	if err != nil {
		log.Fatalf("%sFailed reading report body: %v%s", colorRed, err, colorReset)
	}

	os.Exit(printReport(os.Stdout, bodyBytes, *failOnVulnFlag, *verboseFlag))
}
