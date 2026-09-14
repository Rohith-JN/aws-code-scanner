package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
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
	"github.com/aws/aws-sdk-go-v2/service/codebuild/types"
	codebuildTypes "github.com/aws/aws-sdk-go-v2/service/codebuild/types"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/joho/godotenv"
	"github.com/moby/moby/api/types/registry"
	"github.com/moby/moby/client"
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

	lambdaURL := os.Getenv("LAMBDA_URL")
    
	// 1. Fetch the temporary STS tokens dynamically from the Lambda Function URL
	// REPLACE THIS STRING WITH YOUR ACTUAL LAMBDA URL
 
	
	fmt.Println("Requesting secure upload tokens from AWS...")
	requestBody, _ := json.Marshal(map[string]string{
		"userId": "user-1", // Simulating the logged-in CLI user
	})

	resp, err := http.Post(lambdaURL, "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		panic("failed to connect to Lambda: " + err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		panic(fmt.Sprintf("failed to get tokens, status code: %d", resp.StatusCode))
	}

	var tokens TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		panic("failed to parse Lambda response: " + err.Error())
	}
	fmt.Println("Tokens received successfully!")

	localImage := "project:latest" // Make sure this image actually exists on your machine!
	remoteTag := fmt.Sprintf("%s/%s:latest", tokens.RegistryUri, tokens.RepositoryPath)

	// 2. Configure AWS SDK specifically using the newly fetched temporary STS credentials
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion("ap-south-2"),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			tokens.AccessKeyId,
			tokens.SecretAccessKey,
			tokens.SessionToken,
		)),
	)
	if err != nil {
		panic("unable to load AWS config: " + err.Error())
	}

	// 3. Request the ECR Authorization Token to log into the Docker registry
	ecrClient := ecr.NewFromConfig(cfg)
	authOutput, err := ecrClient.GetAuthorizationToken(ctx, &ecr.GetAuthorizationTokenInput{})
	if err != nil {
		panic("failed to get ECR auth token: " + err.Error())
	}

	authData := authOutput.AuthorizationData[0]
	decodedToken, _ := base64.StdEncoding.DecodeString(*authData.AuthorizationToken)
	password := strings.TrimPrefix(string(decodedToken), "AWS:")

	// 4. Initialize the Docker Client
	cli, err := client.New(client.FromEnv)
	if err != nil {
		panic("failed to init docker client: " + err.Error())
	}

	// 5. Tag the local image 
	_, err = cli.ImageTag(ctx, client.ImageTagOptions{
		Source: localImage,
		Target: remoteTag,
	})
	if err != nil {
		panic("failed to tag image: " + err.Error())
	}

	// 6. Base64-encode the Docker registry credentials
	authConfig := registry.AuthConfig{
		Username:      "AWS",
		Password:      password,
		ServerAddress: tokens.RegistryUri,
	}
	encodedAuth, _ := json.Marshal(authConfig)
	authStr := base64.URLEncoding.EncodeToString(encodedAuth)

	// 7. Execute the push directly to ECR
	fmt.Printf("Pushing %s to ECR...\n", remoteTag)
	pushOutput, err := cli.ImagePush(ctx, remoteTag, client.ImagePushOptions{
		RegistryAuth: authStr,
	})
	if err != nil {
		panic("failed to push image: " + err.Error())
	}
	defer pushOutput.Close()

	io.Copy(os.Stdout, pushOutput)
	fmt.Println("\nSuccessfully pushed image to AWS ECR!")

	// Initialize the CodeBuild client using your existing AWS config (vended via STS)
	cbClient := codebuild.NewFromConfig(cfg)
	projectName := "code-scanner"

	fmt.Printf("Triggering security scan for image: %s\n", remoteTag)

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
		log.Fatalf("failed to start security scan build: %v", err)
	}

	fmt.Println("Security scan build successfully triggered in CodeBuild!")

	// 1. Grab the unique build ID from the start response
    buildID := *startBuildResp.Build.Id
    fmt.Printf("Build started! ID: %s. Waiting for completion...\n", buildID)

    // 2. Poll CodeBuild status
    for {
        batchResp, err := cbClient.BatchGetBuilds(ctx, &codebuild.BatchGetBuildsInput{
            Ids: []string{buildID},
        })
        if err != nil {
            log.Fatalf("failed to check build status: %v", err)
        }
        
        status := batchResp.Builds[0].BuildStatus
        if status == types.StatusTypeInProgress {
            fmt.Print(".")
            time.Sleep(15 * time.Second)
            continue
        }
        
        fmt.Printf("\nScan finished with status: %s\n", status)
        if status != types.StatusTypeSucceeded {
            log.Fatalf("Security scan failed or timed out. Check AWS console for logs.")
        }
        break
    }

    // 3. Construct the exact S3 key used by your buildspec
    
    // Assuming userID is extracted or available from your namespace logic (e.g. "user-1")
    userID := "user-1" 
    s3Key := fmt.Sprintf("reports/%s/codeql-scan-%s.sarif", userID, buildID)
	bucketName := os.Getenv("BUCKET_NAME")

    fmt.Println("Downloading SARIF report from S3...")
    
    // 4. Download file from S3
    s3Client := s3.NewFromConfig(cfg)
    s3Resp, err := s3Client.GetObject(ctx, &s3.GetObjectInput{
        Bucket: aws.String(bucketName),
        Key:    aws.String(s3Key),
    })
    if err != nil {
        log.Fatalf("Failed to download report from S3: %v", err)
    }
    defer s3Resp.Body.Close()

    bodyBytes, _ := io.ReadAll(s3Resp.Body)

    // 5. Parse and Pretty Print
    var report SarifReport
    if err := json.Unmarshal(bodyBytes, &report); err != nil {
        log.Fatalf("Failed to parse SARIF data: %v", err)
    }

    fmt.Println("\n================= SECURITY VULNERABILITIES =================")
    vulnerabilityCount := 0

    if len(report.Runs) > 0 {
        for _, result := range report.Runs[0].Results {
            // Ignore informational telemetry like expected-extracted-files
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
            
            fmt.Printf("[ %s ] Rule: %s\n", strings.ToUpper(result.Level), result.RuleID)
            fmt.Printf("Location : %s:%d\n", fileUri, lineNo)
            fmt.Printf("Details  : %s\n", result.Message.Text)
            fmt.Println("------------------------------------------------------------")
        }
    }

    if vulnerabilityCount == 0 {
        fmt.Println("✅ No vulnerabilities found! Your code passed the security check.")
    } else {
        fmt.Printf("❌ Found %d vulnerabilities.\n", vulnerabilityCount)
    }
    fmt.Println("============================================================")
}