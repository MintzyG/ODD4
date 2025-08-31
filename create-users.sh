#!/bin/bash

# Bulk User Registration Script
# This script will register 100 users with fake data to your API

API_URL="http://localhost:8080/v1/register"  # Adjust port as needed

# Arrays for generating fake data
FIRST_NAMES=("John" "Jane" "Michael" "Sarah" "David" "Emily" "James" "Jessica" "Robert" "Ashley" "William" "Amanda" "Christopher" "Jennifer" "Matthew" "Melissa" "Joshua" "Michelle" "Daniel" "Kimberly")
LAST_NAMES=("Smith" "Johnson" "Williams" "Brown" "Jones" "Garcia" "Miller" "Davis" "Rodriguez" "Martinez" "Hernandez" "Lopez" "Gonzalez" "Wilson" "Anderson" "Thomas" "Taylor" "Moore" "Jackson" "Martin")
EMAIL_DOMAINS=("example.com" "test.com" "fake.com" "demo.com" "sample.com")

# Function to generate a random element from an array
get_random_element() {
    local array=("$@")
    local size=${#array[@]}
    local index=$((RANDOM % size))
    echo "${array[$index]}"
}

# Function to generate a random number between min and max (inclusive)
random_between() {
    local min=$1
    local max=$2
    echo $((RANDOM % (max - min + 1) + min))
}

echo "Starting bulk user registration..."
echo "API URL: $API_URL"
echo ""

SUCCESS_COUNT=0
FAILED_COUNT=0

for i in $(seq 1 100); do
    # Generate random user data
    FIRST_NAME=$(get_random_element "${FIRST_NAMES[@]}")
    LAST_NAME=$(get_random_element "${LAST_NAMES[@]}")
    EMAIL_DOMAIN=$(get_random_element "${EMAIL_DOMAINS[@]}")
    EMAIL="${FIRST_NAME,,}.${LAST_NAME,,}.${i}.sctirandom@${EMAIL_DOMAIN}"
    PASSWORD="password123"
    
    # Random UENF data
    if (( RANDOM % 2 == 0 )); then
        IS_UENF=true
    else
        IS_UENF=false
    fi
    UENF_SEMESTER=$(random_between 1 10)
    
    # Create JSON payload
    JSON_PAYLOAD=$(cat <<EOF
{
    "email": "$EMAIL",
    "password": "$PASSWORD",
    "name": "$FIRST_NAME",
    "last_name": "$LAST_NAME",
    "is_uenf": $IS_UENF,
    "uenf_semester": $UENF_SEMESTER
}
EOF
)

    # Make the API call
    RESPONSE=$(curl -s -w "HTTPSTATUS:%{http_code}" \
        -X POST \
        -H "Content-Type: application/json" \
        -d "$JSON_PAYLOAD" \
        "$API_URL")
    
    # Extract HTTP status code
    HTTP_STATUS=$(echo "$RESPONSE" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')
    RESPONSE_BODY=$(echo "$RESPONSE" | sed -e 's/HTTPSTATUS:.*//g')
    
    # Check if successful
    if [ "$HTTP_STATUS" -eq 201 ]; then
        echo "✅ User $i: $FIRST_NAME $LAST_NAME ($EMAIL) - SUCCESS"
        ((SUCCESS_COUNT++))
    else
        echo "❌ User $i: $FIRST_NAME $LAST_NAME ($EMAIL) - FAILED (HTTP: $HTTP_STATUS)"
        echo "   Response: $RESPONSE_BODY"
        ((FAILED_COUNT++))
    fi
    
    # Small delay to avoid overwhelming the server
    sleep 0.1
done

echo ""
echo "===== REGISTRATION SUMMARY ====="
echo "Total users attempted: 100"
echo "Successful registrations: $SUCCESS_COUNT"
echo "Failed registrations: $FAILED_COUNT"
echo ""

if [ $SUCCESS_COUNT -gt 0 ]; then
    echo "✅ Script completed successfully!"
    echo "You can now test the users endpoint:"
    echo "  GET $API_URL/../users?page=1&limit=10"
    echo "  GET $API_URL/../users?id=<user_id>"
else
    echo "❌ No users were registered successfully."
    echo "Please check:"
    echo "  1. Is your API server running?"
    echo "  2. Is the API_URL correct?"
    echo "  3. Are there any validation errors?"
fi

echo ""
echo "Note: All users are registered with password 'password123'"