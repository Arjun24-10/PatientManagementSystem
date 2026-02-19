# Quick Setup Guide for Teammates

## Run Tests in 3 Steps

1. Clone and checkout:
   git checkout frontend-integration-tests
   cd frontend/app

2. Install dependencies:
   npm install

3. Run tests:
   npm test -- --watchAll=false

## If Tests Fail

Run this:
cd frontend/app
rm -rf node_modules package-lock.json
npm cache clean --force
npm install
npm test -- --watchAll=false

## Expected Result
Test Suites: 44 passed, 44 total
Tests: 124 passed, 124 total
