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

type SarifReport struct {
	Runs []struct {
		Results []struct {
			RuleID  string `json:"ruleId"`
			Level   string `json:"level"`
			Message struct {
				Text string `json:"text"`
			} `json:"message"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
					Region struct {
						StartLine int `json:"startLine"`
					} `json:"region"`
				} `json:"physicalLocation"`
			} `json:"locations"`
		} `json:"results"`
	} `json:"runs"`
}

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
	flag.BoolVar(verboseFlag, "v", false, "Shorthand for --verbose")
	failOnVulnFlag := flag.Bool("fail-on-vuln", true, "Exit with non-zero code if security issues are discovered")
	flag.Parse()

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

	pushOutput, err := cli.ImagePush(ctx, remoteTag, client.ImagePushOptions{
		RegistryAuth: authStr,
	})
	if err != nil {
		log.Fatalf("%sFailed to push image to ECR: %v%s", colorRed, err, colorReset)
	}
	defer pushOutput.Close()

	if *verboseFlag {
		io.Copy(os.Stdout, pushOutput)
	} else {
		// Discard verbose layer logs in minimal mode
		io.Copy(io.Discard, pushOutput)
	}

	// 4. Trigger CodeBuild Security Scan
	logStep(3, 4, "Triggering CodeQL security analysis...")
	cbClient := codebuild.NewFromConfig(cfg)

	startBuildResp, err := cbClient.StartBuild(ctx, &codebuild.StartBuildInput{
		ProjectName: &projectName,
		EnvironmentVariablesOverride: []codebuildTypes.EnvironmentVariable{
			{
				Name:  aws.String("IMAGE_URI"),
				Value: aws.String(remoteTag),
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

	var report SarifReport
	if err := json.Unmarshal(bodyBytes, &report); err != nil {
		log.Fatalf("%sFailed parsing SARIF JSON: %v%s", colorRed, err, colorReset)
	}

	// 6. Pretty Print Findings
	fmt.Println()
	fmt.Printf("%s%s====================== SCAN RESULTS ======================%s\n", colorBold, colorCyan, colorReset)

	vulnerabilityCount := 0

	if len(report.Runs) > 0 {
		for _, result := range report.Runs[0].Results {
			if result.Level == "none" || strings.Contains(result.RuleID, "expected-extracted") {
				continue
			}

			vulnerabilityCount++
			fileUri := "Unknown"
			lineNo := 0

			if len(result.Locations) > 0 {
				fileUri = result.Locations[0].PhysicalLocation.ArtifactLocation.URI
				lineNo = result.Locations[0].PhysicalLocation.Region.StartLine
			}

			levelBadge := fmt.Sprintf("%s%s[%s]%s", colorBold, colorRed, strings.ToUpper(result.Level), colorReset)
			if strings.EqualFold(result.Level, "warning") {
				levelBadge = fmt.Sprintf("%s%s[%s]%s", colorBold, colorYellow, strings.ToUpper(result.Level), colorReset)
			}

			fmt.Printf("%s %s%s%s\n", levelBadge, colorBold, result.RuleID, colorReset)
			fmt.Printf("   %s-->%s %s:%d\n", colorCyan, colorReset, fileUri, lineNo)
			fmt.Printf("   %s\n\n", result.Message.Text)
		}
	}

	fmt.Printf("%s%s==========================================================%s\n", colorBold, colorCyan, colorReset)

	if vulnerabilityCount == 0 {
		fmt.Printf("%s%s✔ SUCCESS: No security vulnerabilities found.%s\n\n", colorBold, colorGreen, colorReset)
		os.Exit(0)
	} else {
		fmt.Printf("%s%s✖ FAILED: Found %d security vulnerabilities.%s\n\n", colorBold, colorRed, vulnerabilityCount, colorReset)
		if *failOnVulnFlag {
			os.Exit(1)
		}
	}
}