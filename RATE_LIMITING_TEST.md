# Rate Limiting Test

This is a simple test to verify that rate limiting is working correctly.

## Prerequisites

1. Ensure the server is running
2. Have curl installed
3. Set up environment variables for testing

## Test Setup

Create a `.env` file with strict rate limiting for testing:

```bash
# Test configuration - very strict limits
RATE_LIMIT_REQUESTS=3
RATE_LIMIT_WINDOW_SECONDS=60

# Very strict login limits
RATE_LIMIT_POST_AUTH_LOGIN_REQUESTS=2
RATE_LIMIT_POST_AUTH_LOGIN_WINDOW=60

# Other required variables
DATABASE_URL=postgresql://dbuser:dbpassword@localhost/ilma_db
JWT_SECRET=your-super-secret-jwt-key-that-is-at-least-32-characters-long
BIND_ADDRESS=127.0.0.1:8000
```

## Test Commands

### Test Global Rate Limiting

```bash
# Test global rate limiting with GET requests
for i in {1..5}; do
  echo "Request $i:"
  curl -w "HTTP Status: %{http_code}\n" -s -o /dev/null http://localhost:8000/swagger-ui/
  sleep 1
done
```

### Test Per-Endpoint Rate Limiting (Login)

```bash
# Test login rate limiting
for i in {1..4}; do
  echo "Login attempt $i:"
  curl -X POST \
    -H "Content-Type: application/json" \
    -d '{"username":"testuser","password":"testpass"}' \
    -w "HTTP Status: %{http_code}\n" \
    -s -o /dev/null \
    http://localhost:8000/api/auth/login
  sleep 1
done
```

### Test Rate Limiting with JSON Response

```bash
# Test to see the actual JSON response when rate limited
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"testpass"}' \
  -w "\nHTTP Status: %{http_code}\n" \
  http://localhost:8000/api/auth/login
```

## Expected Results

1. **Global Rate Limiting**: After 3 requests within 60 seconds, you should receive `429 Too Many Requests`
2. **Login Rate Limiting**: After 2 login attempts within 60 seconds, you should receive `429 Too Many Requests`
3. **JSON Response**: The rate limit response should include error details and the specific endpoint

## Automated Test Script

Save this as `test_rate_limiting.sh`:

```bash
#!/bin/bash

echo "Testing Rate Limiting..."
echo "========================"

BASE_URL="http://localhost:8000"
COUNTER=0

echo "1. Testing global rate limiting..."
for i in {1..5}; do
  COUNTER=$((COUNTER + 1))
  STATUS=$(curl -w "%{http_code}" -s -o /dev/null "$BASE_URL/swagger-ui/")
  echo "Request $COUNTER: HTTP $STATUS"
  if [ "$STATUS" = "429" ]; then
    echo "✓ Rate limiting triggered at request $COUNTER"
    break
  fi
  sleep 1
done

echo ""
echo "2. Testing login endpoint rate limiting..."
COUNTER=0
for i in {1..4}; do
  COUNTER=$((COUNTER + 1))
  STATUS=$(curl -X POST \
    -H "Content-Type: application/json" \
    -d '{"username":"testuser","password":"testpass"}' \
    -w "%{http_code}" \
    -s -o /dev/null \
    "$BASE_URL/api/auth/login")
  echo "Login attempt $COUNTER: HTTP $STATUS"
  if [ "$STATUS" = "429" ]; then
    echo "✓ Login rate limiting triggered at attempt $COUNTER"
    break
  fi
  sleep 1
done

echo ""
echo "3. Getting rate limit response details..."
RESPONSE=$(curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"testpass"}' \
  -w "\nHTTP_STATUS:%{http_code}" \
  "$BASE_URL/api/auth/login" 2>/dev/null)

echo "Response: $RESPONSE"
echo ""
echo "Test completed!"
```

Make it executable and run:

```bash
chmod +x test_rate_limiting.sh
./test_rate_limiting.sh
```

## PowerShell Test Script (Windows)

Save this as `test_rate_limiting.ps1`:

```powershell
Write-Host "Testing Rate Limiting..." -ForegroundColor Green
Write-Host "========================" -ForegroundColor Green

$BaseUrl = "http://localhost:8000"
$Counter = 0

Write-Host "1. Testing global rate limiting..." -ForegroundColor Yellow
for ($i = 1; $i -le 5; $i++) {
    $Counter++
    try {
        $response = Invoke-WebRequest -Uri "$BaseUrl/swagger-ui/" -Method GET -UseBasicParsing
        $status = $response.StatusCode
    } catch {
        $status = $_.Exception.Response.StatusCode.value__
    }

    Write-Host "Request $Counter`: HTTP $status"
    if ($status -eq 429) {
        Write-Host "✓ Rate limiting triggered at request $Counter" -ForegroundColor Green
        break
    }
    Start-Sleep -Seconds 1
}

Write-Host ""
Write-Host "2. Testing login endpoint rate limiting..." -ForegroundColor Yellow
$Counter = 0
$LoginData = @{
    username = "testuser"
    password = "testpass"
} | ConvertTo-Json

for ($i = 1; $i -le 4; $i++) {
    $Counter++
    try {
        $response = Invoke-WebRequest -Uri "$BaseUrl/api/auth/login" -Method POST -Body $LoginData -ContentType "application/json" -UseBasicParsing
        $status = $response.StatusCode
    } catch {
        $status = $_.Exception.Response.StatusCode.value__
    }

    Write-Host "Login attempt $Counter`: HTTP $status"
    if ($status -eq 429) {
        Write-Host "✓ Login rate limiting triggered at attempt $Counter" -ForegroundColor Green
        break
    }
    Start-Sleep -Seconds 1
}

Write-Host ""
Write-Host "Test completed!" -ForegroundColor Green
```

Run with:

```powershell
.\test_rate_limiting.ps1
```
